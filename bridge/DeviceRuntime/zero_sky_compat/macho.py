"""Bounded Mach-O load-command parser, with no binary mutation or execution."""
import struct
from pathlib import Path

CPUS = {0x100000c: 'arm64', 0x1000007: 'x86_64', 12: 'arm'}
LOADS = {0xc, 0x18, 0x80000018, 0x1f, 0x8000001f, 0x80000023}


def version(value):
    return '%d.%d.%d' % (value >> 16, (value >> 8) & 255, value & 255)


def parse(path):
    path = Path(path)
    size = path.stat().st_size
    with path.open('rb') as stream:
        header = stream.read(8)
        if header[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf',
                          b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca'):
            endian = '>' if header[:4] in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf') else '<'
            count = struct.unpack_from(endian + 'I', header, 4)[0]
            wide = header[:4] in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
            stride = 32 if wide else 20
            table_size = 8 + count * stride
            if count == 0 or count > 32 or table_size > size:
                raise ValueError('invalid fat Mach-O header')
            stream.seek(0)
            table = stream.read(table_size)
            slices = []
            for i in range(count):
                row = struct.unpack_from(endian + ('IIQQII' if wide else 'IIIII'),
                                         table, 8 + i * stride)
                offset, extent = row[2:4]
                if offset < table_size or extent < 28 or offset + extent > size:
                    raise ValueError('invalid fat Mach-O slice')
                slices.append(_thin_stream(stream, offset, extent))
            return slices
        return [_thin_stream(stream, 0, size)]


def _thin_stream(stream, offset, extent):
    stream.seek(offset)
    header = stream.read(32)
    formats = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xce\xfa\xed\xfe': ('<', 28),
               b'\xfe\xed\xfa\xcf': ('>', 32), b'\xfe\xed\xfa\xce': ('>', 28)}
    if header[:4] not in formats:
        raise ValueError('invalid Mach-O magic')
    endian, header_size = formats[header[:4]]
    if extent < header_size:
        raise ValueError('truncated Mach-O header')
    command_size = struct.unpack_from(endian + 'I', header, 20)[0]
    if command_size > 16 * 1024 * 1024 or header_size + command_size > extent:
        raise ValueError('invalid load command bounds')
    stream.seek(offset)
    data = stream.read(header_size + command_size)
    return thin(data, file_size=extent)


def thin(data, file_size=None):
    formats = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xce\xfa\xed\xfe': ('<', 28),
               b'\xfe\xed\xfa\xcf': ('>', 32), b'\xfe\xed\xfa\xce': ('>', 28)}
    if data[:4] not in formats:
        raise ValueError('invalid Mach-O magic')
    endian, header_size = formats[data[:4]]
    if len(data) < header_size:
        raise ValueError('truncated Mach-O header')
    _, cpu, subtype, filetype, count, size, flags = struct.unpack_from(endian + '7I', data)
    end = header_size + size
    if count > 65536 or end > len(data):
        raise ValueError('invalid load command bounds')
    architecture = CPUS.get(cpu, 'unknown')
    if architecture == 'arm64' and (subtype & 0xffffff) == 2:
        architecture = 'arm64e'
    result = {'architecture': architecture,
              'cpu_subtype': subtype & 0xffffff, 'filetype': filetype,
              'dependencies': [], 'rpaths': [], 'install_name': None,
              'minimum_os': None, 'platform': None, 'signed': False}
    offset = header_size
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError('truncated load command')
        command, length = struct.unpack_from(endian + 'II', data, offset)
        if length < 8 or offset + length > end:
            raise ValueError('invalid load command length')
        if command in LOADS or command in (0xd, 0x8000001c):
            if length < 12:
                raise ValueError('invalid string command')
            start = struct.unpack_from(endian + 'I', data, offset + 8)[0]
            if start < 12 or start >= length:
                raise ValueError('invalid load command string')
            raw = data[offset + start:offset + length].split(b'\0', 1)
            if len(raw) != 2:
                raise ValueError('unterminated load command string')
            value = raw[0].decode('utf-8', 'strict')
            if command == 0x8000001c:
                result['rpaths'].append(value)
            elif command == 0xd:
                result['install_name'] = value
            else:
                result['dependencies'].append({'name': value, 'optional': command in (0x18, 0x80000018)})
        elif command == 0x32:
            if length < 24:
                raise ValueError('invalid build version command')
            platform, minimum = struct.unpack_from(endian + 'II', data, offset + 8)
            result.update(platform=platform, minimum_os=version(minimum))
        elif command == 0x25:
            if length < 16:
                raise ValueError('invalid minimum version command')
            result.update(platform=2, minimum_os=version(struct.unpack_from(endian + 'I', data, offset + 8)[0]))
        elif command == 0x1d:
            if length < 16:
                raise ValueError('invalid code signature command')
            start, size = struct.unpack_from(endian + 'II', data, offset + 8)
            if start + size > (file_size if file_size is not None else len(data)):
                raise ValueError('invalid signature bounds')
            result['signed'] = size > 0
        offset += length
    if offset != end:
        raise ValueError('load command count mismatch')
    return result
