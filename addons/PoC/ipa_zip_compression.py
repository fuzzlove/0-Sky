def normalize_zip_compression(path):
    """Rewrite supported ZIP methods that macOS ditto cannot extract."""
    import copy
    import struct
    import tempfile

    def strip_zip64(extra):
        result = bytearray()
        offset = 0
        while offset < len(extra):
            if offset + 4 > len(extra):
                raise RuntimeError("IPA has malformed ZIP metadata")
            tag, size = struct.unpack_from("<HH", extra, offset)
            end = offset + 4 + size
            if end > len(extra):
                raise RuntimeError("IPA has truncated ZIP metadata")
            if tag != 1:
                result.extend(extra[offset:end])
            offset = end
        return bytes(result)

    temporary = None
    try:
        with zipfile.ZipFile(path) as source:
            entries = source.infolist()
            if len(entries) > MAX_IPA_ENTRIES:
                raise RuntimeError("IPA contains too many archive entries")
            expanded = sum(item.file_size for item in entries)
            if expanded > 16 * 1024 * 1024 * 1024:
                raise RuntimeError("IPA expansion exceeds the 16 GiB safety limit")
            methods = {item.compress_type for item in entries}
            if methods <= {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                return False
            if not methods <= {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                               zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}:
                raise RuntimeError("IPA uses an unsupported ZIP compression method")
            if shutil.disk_usage(path.parent).free < expanded + MIN_WORKSPACE_HEADROOM:
                raise RuntimeError("Insufficient host space to normalize IPA compression")
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".ipa-compression-",
                                             suffix=".zip", delete=False) as handle:
                temporary = pathlib.Path(handle.name)
            total = 0
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED,
                                 allowZip64=True) as destination:
                destination.comment = source.comment
                for item in entries:
                    clone = copy.copy(item)
                    clone.compress_type = (zipfile.ZIP_STORED if item.is_dir()
                                           else zipfile.ZIP_DEFLATED)
                    clone.extra = strip_zip64(item.extra)
                    # Copy bytes unchanged, including symlink targets. Preserve
                    # Unix modes, names, dates, comments and non-ZIP64 metadata.
                    written = 0
                    with source.open(item) as incoming, destination.open(clone, "w") as outgoing:
                        while True:
                            chunk = incoming.read(1024 * 1024)
                            if not chunk:
                                break
                            written += len(chunk)
                            total += len(chunk)
                            if written > item.file_size or total > expanded:
                                raise RuntimeError("IPA expands beyond its declared size")
                            outgoing.write(chunk)
                    if written != item.file_size:
                        raise RuntimeError("IPA member size mismatch")
        temporary.replace(path)
        return True
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
