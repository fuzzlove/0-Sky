#!/usr/bin/env python3
"""Personalize and install one Cryptex on an authorized iOS 17+ SRD.

The installer tries Apple's native remoted transport first and then the
pymobiledevice3 userspace USB transport.  It obtains the research nonce and TSS
ticket before retiring an existing generation.  No retail-device bypass is
implemented: if neither authorized service path succeeds, the enforcement
boundary is reported and left intact.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import sys
import time

from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel
from pymobiledevice3.remote.xpc_message import XpcUInt64Type
from pymobiledevice3.restore.tss import TSSRequest
from pymobiledevice3.services.cryptexd import CryptexdService


# An earlier SRDssh generation used this Cryptex identifier.  Some upgraded
# devices legitimately retain both generations; after reboot its old
# Dropbear job can win the port-22 race and present a different host key.
# Retire only this exact owned identifier, and only after the positive SRD +
# nonce + TSS preflight has completed.
LEGACY_SRDSH_IDENTIFIERS = ("com.jonpalmisc.srdsh",)


def image_type_index_for(product_version: object) -> int:
    """Return the measured GenericDmg slot for supported SRD OS families."""
    try:
        parts = str(product_version).split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (TypeError, ValueError, IndexError) as error:
        raise RuntimeError(
            "Device did not report a usable OS version for Cryptex installation"
        ) from error
    if major == 26:
        return 9 if minor <= 3 else 10
    if major == 27:
        return 10
    raise RuntimeError(
        f"Unsupported SRD OS for Cryptex installation: {product_version}; "
        "verified families are iOS 26 and iOS 27"
    )


def der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der_ia5(value: str) -> bytes:
    encoded = value.encode("ascii")
    return b"\x16" + der_length(len(encoded)) + encoded


def der_octets(value: bytes) -> bytes:
    return b"\x04" + der_length(len(value)) + value


def der_sequence(*parts: bytes) -> bytes:
    body = b"".join(parts)
    return b"\x30" + der_length(len(body)) + body


def make_identity(template: dict, info: bytes, trust: bytes,
                  volume_hash: bytes, image: bytes) -> dict:
    identity = copy.deepcopy(template["BuildIdentities"][0])
    identity.update({
        "Cryptex1,UseProductClass": True,
        "Cryptex1,ChipID": "0xff10",
        "Cryptex1,ProductClass": "0xf2",
        "Cryptex1,Type": 3,
        "Cryptex1,SubType": 255,
        "Cryptex1,NonceDomain": 3,
        "Cryptex1,Version": "999.999.999.999.999,999",
        "Cryptex1,PreauthorizationVersion": "999.999.999.999.999,999",
    })
    for key, data in (
        ("Cryptex1,CryptexInfoPlist", info),
        ("Cryptex1,GenericTrustCache", trust),
        ("Cryptex1,GenericVolume", volume_hash),
        ("Cryptex1,GenericDmg", image),
    ):
        entry = identity["Manifest"].setdefault(key, {"Info": {}})
        entry["Digest"] = hashlib.sha384(data).digest()
        entry.setdefault("Info", {})["Personalize"] = True
    return identity


def sha384(data: bytes) -> str:
    return hashlib.sha384(data).hexdigest()


def _expected_udid_bytes(udid: str) -> bytes:
    """Return the 16-byte UDID representation used by Cryptex TSS requests."""
    try:
        compact = bytes.fromhex(udid.replace("-", ""))
    except ValueError as error:
        raise RuntimeError("the configured UDID is not hexadecimal") from error
    if len(compact) > 16:
        raise RuntimeError("the configured UDID is too long for a Cryptex ticket")
    return compact.rjust(16, b"\0")


def cached_ticket(
    cache_root: Path,
    *,
    udid: str,
    nonce: bytes,
    identifier: str,
    version: str,
    image: bytes,
    trust: bytes,
    hash_data: bytes,
    build_manifest: bytes,
    identity: dict,
) -> tuple[bytes, Path] | None:
    """Select an exact, internally consistent cached TSS response.

    Cache use is intentionally subordinate to the live SRD guard in
    :func:`attempt`.  This routine does not classify a device and must never be
    called before cryptexd has returned a fresh domain-3 nonce. When the
    research indicator is not positive, cache reuse is disabled and a fresh
    live TSS authorization is mandatory.
    A directory is accepted only when its metadata, request, response, ticket,
    exact UDID, live nonce, profile, and all personalized input digests agree.
    """
    supplied_root = cache_root.expanduser()
    if supplied_root.is_symlink():
        raise RuntimeError(f"cached-ticket root is missing or unsafe: {supplied_root}")
    root = supplied_root.resolve()
    if not root.is_dir():
        raise RuntimeError(f"cached-ticket root is missing or unsafe: {root}")
    expected_inputs = {
        "image": sha384(image),
        "trust_cache": sha384(trust),
        "volume_hash": sha384(hash_data),
        "manifest": sha384(build_manifest),
    }
    expected_request_digests = {
        key: value["Digest"]
        for key, value in identity["Manifest"].items()
        if key in {
            "Cryptex1,CryptexInfoPlist",
            "Cryptex1,GenericTrustCache",
            "Cryptex1,GenericVolume",
            "Cryptex1,GenericDmg",
        }
    }
    expected_udid = _expected_udid_bytes(udid)
    candidates = sorted(
        root.glob(f"*-{udid}-d3-*/metadata.json"),
        key=lambda path: path.parent.name,
        reverse=True,
    )
    for metadata_path in candidates:
        directory = metadata_path.parent
        required = {
            "metadata": metadata_path,
            "request": directory / "request.plist",
            "response": directory / "response.plist",
            "nonce": directory / "nonce.bin",
            "ticket": directory / "Cryptex1-Ticket.im4m",
        }
        if directory.is_symlink() or any(
            path.is_symlink() or not path.is_file() for path in required.values()
        ):
            continue
        try:
            metadata = json.loads(required["metadata"].read_text(encoding="utf-8"))
            request = plistlib.loads(required["request"].read_bytes())
            response = plistlib.loads(required["response"].read_bytes())
            cached_nonce = required["nonce"].read_bytes()
            ticket = required["ticket"].read_bytes()
        except (OSError, ValueError, plistlib.InvalidFileException):
            continue
        profile = metadata.get("profile", {})
        if (
            metadata.get("udid") != udid
            or metadata.get("nonce_domain") != 3
            or metadata.get("nonce_hex") != nonce.hex()
            or cached_nonce != nonce
            or profile.get("identifier") != identifier
            or profile.get("version") != version
            or metadata.get("input_sha384") != expected_inputs
            or metadata.get("ticket_length") != len(ticket)
            or metadata.get("ticket_sha256") != hashlib.sha256(ticket).hexdigest()
            or response.get("Cryptex1,Ticket") != ticket
            or request.get("@Cryptex1,Ticket") is not True
            or request.get("Cryptex1,NonceDomain") != 3
            or request.get("Cryptex1,Nonce") != nonce
            or request.get("Cryptex1,UDID") != expected_udid
            or request.get("Cryptex1,Version") != identity["Cryptex1,Version"]
            or request.get("Cryptex1,PreauthorizationVersion")
                != identity["Cryptex1,PreauthorizationVersion"]
        ):
            continue
        if any(
            not isinstance(request.get(key), dict)
            or request[key].get("Digest") != digest
            for key, digest in expected_request_digests.items()
        ):
            continue
        return ticket, directory
    return None


async def attempt(args: argparse.Namespace, *, prefer_native: bool,
                  mutate: bool) -> dict:
    image = args.image.read_bytes()
    trust = args.trust_cache.read_bytes()
    hash_data = args.volume_hash.read_bytes()
    template = plistlib.loads(args.build_manifest.read_bytes())
    info = plistlib.dumps({
        "CFBundleIdentifier": args.identifier,
        "CFBundleVersion": args.version,
        "DeveloperModeRequired": True,
    }, fmt=plistlib.FMT_XML, sort_keys=True)
    volume_hash = der_sequence(
        der_ia5("IM4P"), der_ia5("gtgv"), der_ia5("0"), der_octets(hash_data)
    )
    identity = make_identity(template, info, trust, volume_hash, image)
    started = time.monotonic()
    async with PreferredRsdTunnel(
        serial=args.udid, autopair=True, prefer_native=prefer_native
    ) as rsd:
        if str(rsd.udid) != args.udid:
            raise RuntimeError(f"RemoteXPC selected {rsd.udid}, not {args.udid}")
        transport = "userspace-usb" if rsd.is_in_process_tunnel else "native-remoted"
        service = CryptexdService(rsd)
        image_type_index = image_type_index_for(
            getattr(rsd, "product_version", None)
        )
        print(
            f"[0-Sky Cryptex] selected GenericDmg image index "
            f"{image_type_index} for iOS {rsd.product_version}",
            flush=True,
        )
        identifiers = await asyncio.wait_for(
            service.read_personalization_identifiers(), timeout=30
        )
        research_enabled = identifiers.get("img4_chip_rsch")
        nonce = await asyncio.wait_for(service.cryptex_nonce(3), timeout=30)
        if not nonce:
            raise RuntimeError("cryptexd returned an empty research-domain nonce")
        selected_cache: Path | None = None
        ticket: bytes | None = None
        # Current iOS 27 builds can report a non-positive legacy research
        # indicator on an Apple-authorized target. In that case never reuse a
        # cache: require Apple TSS to authorize this exact live nonce now.
        if args.ticket_cache is not None and research_enabled == 1:
            selected = cached_ticket(
                args.ticket_cache,
                udid=args.udid,
                nonce=nonce,
                identifier=args.identifier,
                version=args.version,
                image=image,
                trust=trust,
                hash_data=hash_data,
                build_manifest=args.build_manifest.read_bytes(),
                identity=identity,
            )
            if selected is not None:
                ticket, selected_cache = selected
        if ticket is None:
            if args.require_cached_ticket:
                raise RuntimeError(
                    "no cached ticket exactly matches this live SRD, nonce, profile, "
                    "and personalized input set"
                )
            request = TSSRequest()
            request.add_cryptex1_tags(identity, identifiers, nonce)
            response = await asyncio.wait_for(request.send_receive(), timeout=90)
            ticket = response.get("Cryptex1,Ticket")
            if not isinstance(ticket, (bytes, bytearray)) or not ticket:
                raise RuntimeError("Apple TSS did not authorize a Cryptex1 ticket")
        result = {
            "udid": args.udid,
            "product_type": str(rsd.product_type),
            "product_version": str(rsd.product_version),
            "transport": transport,
            "research_identifier_present": "img4_chip_rsch" in identifiers,
            "research_identifier_value": identifiers.get("img4_chip_rsch"),
            "nonce_length": len(nonce),
            "ticket_length": len(ticket),
            "ticket_source": "cache" if selected_cache else "live-tss",
            "authorization_basis": (
                "positive-identifier+exact-cache" if selected_cache
                else "exact-udid+fresh-domain3-nonce+live-tss-ticket"
            ),
            "ticket_cache_entry": str(selected_cache) if selected_cache else None,
            "mutated": False,
        }
        print(json.dumps(result, sort_keys=True), flush=True)
        if not mutate:
            return result

        # Only mutate after identity, nonce, and TSS authorization all succeed.
        # Query first and fail closed if an exact owned generation cannot be
        # retired; installing beside it can produce duplicate launch jobs and
        # a reboot-dependent SSH identity.
        installed = await asyncio.wait_for(service.copy_installed(), timeout=45)
        present = {str(item.identifier) for item in installed}
        retirement = [identifier for identifier in
                      (*LEGACY_SRDSH_IDENTIFIERS, args.identifier)
                      if identifier in present]
        for identifier in retirement:
            await asyncio.wait_for(service.uninstall(identifier), timeout=45)
        result["retired_identifiers"] = retirement
        # Retiring a persistent generation can rotate the domain-3 nonce.  A
        # ticket obtained before that transition then authenticates the old
        # nonce and the next mount fails with hdi authentication error.  Keep
        # the pre-retirement TSS authorization as the gate for mutation, then
        # bind the installation itself to the post-retirement nonce.
        if retirement:
            post_retirement_identifiers = await asyncio.wait_for(
                service.read_personalization_identifiers(), timeout=30)
            post_retirement_nonce = await asyncio.wait_for(
                service.cryptex_nonce(3), timeout=30)
            if not post_retirement_nonce:
                raise RuntimeError(
                    "cryptexd returned an empty post-retirement research nonce")
            if post_retirement_nonce != nonce:
                post_request = TSSRequest()
                post_request.add_cryptex1_tags(
                    identity, post_retirement_identifiers, post_retirement_nonce)
                post_response = await asyncio.wait_for(
                    post_request.send_receive(), timeout=90)
                post_ticket = post_response.get("Cryptex1,Ticket")
                if not isinstance(post_ticket, (bytes, bytearray)) or not post_ticket:
                    raise RuntimeError(
                        "Apple TSS did not authorize the post-retirement Cryptex1 ticket")
                nonce = post_retirement_nonce
                ticket = post_ticket
                result["nonce_length"] = len(nonce)
                result["ticket_length"] = len(ticket)
                result["ticket_source"] = "live-tss-post-retirement"
                result["authorization_basis"] = (
                    "exact-udid+post-retirement-domain3-nonce+live-tss-ticket")
                print(
                    "[0-Sky Cryptex] domain-3 nonce rotated during retirement; "
                    "installation ticket refreshed through live TSS",
                    flush=True,
                )
        properties = {
            "Cryptex1,UseProductClass": True,
            "MountedCryptex": False,
            "Cryptex1,SubType": XpcUInt64Type(255),
            "Cryptex1,NonceDomain": XpcUInt64Type(3),
            "Cryptex1,Version": identity["Cryptex1,Version"],
            "Cryptex1,PreauthVersion": identity["Cryptex1,PreauthorizationVersion"],
        }
        await asyncio.wait_for(service.install(
            image, trust, ticket, info, volume_hash, properties,
            image_type_index=image_type_index, persistence=2,
            nonce_persistence=1, auth=0,
        ), timeout=args.timeout)
        result["mutated"] = True
        result["elapsed_seconds"] = round(time.monotonic() - started, 2)
        print("INSTALL SUCCESS " + json.dumps(result, sort_keys=True), flush=True)
        return result


async def installed_after_lost_reply(args: argparse.Namespace) -> bool:
    """Verify completion on a fresh channel when cryptexd drops its reply."""
    async with PreferredRsdTunnel(serial=args.udid, autopair=True) as rsd:
        service = CryptexdService(rsd)
        installed = await asyncio.wait_for(service.copy_installed(), timeout=45)
        return any(
            item.identifier == args.identifier and item.version == args.version
            for item in installed
        )


def boundary(error: BaseException) -> str:
    text = str(error).lower()
    if any(word in text for word in ("pair", "remoted", "device not found", "tunnel")):
        return (
            "ENFORCING_COMPONENT=remotepairingd/Lockdown\n"
            "ENFORCEMENT_MECHANISM=Exact-UDID Developer Mode pairing\n"
            "REQUIRED_AUTHORIZATION_OR_ENTITLEMENT=Approve this Mac under Settings > Developer > Paired Macs"
        )
    if any(word in text for word in ("denied", "permission", "not permitted", "tss", "nonce")):
        return (
            "ENFORCING_COMPONENT=cryptexd/TSS\n"
            "ENFORCEMENT_MECHANISM=Research nonce and personalized Cryptex ticket validation\n"
            "REQUIRED_AUTHORIZATION_OR_ENTITLEMENT=Authorized SRD research personalization service"
        )
    return (
        "ENFORCING_COMPONENT=RemoteXPC transport or cryptexd\n"
        "ENFORCEMENT_MECHANISM=Transport/service failure before confirmed installation\n"
        "REQUIRED_AUTHORIZATION_OR_ENTITLEMENT=Developer Mode, exact-UDID pairing, and SRD personalization"
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("identifier")
    p.add_argument("image", type=Path)
    p.add_argument("trust_cache", type=Path)
    p.add_argument("volume_hash", type=Path)
    p.add_argument("version")
    p.add_argument("udid")
    p.add_argument("build_manifest", type=Path)
    p.add_argument("--preflight", action="store_true")
    p.add_argument(
        "--ticket-cache", type=Path,
        help=(
            "optional research-nonces directory; an entry is used only after "
            "a live exact-UDID domain-3 nonce; a non-positive legacy indicator forces live TSS authorization"
        ),
    )
    p.add_argument(
        "--require-cached-ticket", action="store_true",
        help="fail instead of contacting TSS when no exact safe cache match exists",
    )
    p.add_argument(
        "--timeout", type=int, default=900,
        help="maximum seconds for each complete transport attempt (default: 900)",
    )
    p.add_argument(
        "--transport", choices=("auto", "native", "userspace"), default="auto",
        help=(
            "RemoteXPC route: auto tries native then USB userspace; use userspace "
            "to recover when macOS remoted accepts a connection but stalls"
        ),
    )
    return p.parse_args()


async def bounded(coroutine, timeout: int):
    """Apply the advertised bound to the complete asynchronous transition."""
    return await asyncio.wait_for(coroutine, timeout=timeout)


def main() -> int:
    args = parse_args()
    if args.timeout <= 0:
        raise SystemExit("--timeout must be a positive number of seconds")
    if args.require_cached_ticket and args.ticket_cache is None:
        raise SystemExit("--require-cached-ticket requires --ticket-cache")
    for item in (args.image, args.trust_cache, args.volume_hash, args.build_manifest):
        if not item.is_file():
            raise SystemExit(f"missing Cryptex input: {item}")
    errors: list[str] = []
    # Attempt 1 prefers Apple's native remoted route. Attempt 2 explicitly
    # forces the no-root userspace USB route, including cases where the native
    # tunnel connected but the service transition was denied or interrupted.
    attempts = {
        "auto": (("native-preferred", True), ("userspace-usb", False)),
        "native": (("native-only", True),),
        "userspace": (("userspace-usb", False),),
    }[args.transport]
    for label, prefer_native in attempts:
        try:
            print(f"[0-Sky Cryptex] attempt={label}", flush=True)
            asyncio.run(bounded(
                attempt(args, prefer_native=prefer_native,
                        mutate=not args.preflight),
                args.timeout,
            ))
            return 0
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as error:
            if isinstance(error, TimeoutError) and not args.preflight:
                try:
                    if asyncio.run(bounded(
                            installed_after_lost_reply(args),
                            min(args.timeout, 60))):
                        print(
                            "INSTALL SUCCESS " + args.identifier
                            + " (verified after cryptexd omitted its terminal reply)",
                            flush=True,
                        )
                        return 0
                except Exception as verify_error:
                    errors.append(
                        f"post-timeout verification: {type(verify_error).__name__}: {verify_error}"
                    )
            errors.append(f"{label}: {type(error).__name__}: {error}")
            print(f"[0-Sky Cryptex] {errors[-1]}", file=sys.stderr, flush=True)
    detail = "\n".join(errors)
    print("\n" + boundary(RuntimeError(detail)), file=sys.stderr)
    print("FIRST_FAILING_TRANSITION=Mac RemoteXPC -> cryptexd research service", file=sys.stderr)
    print("SUPPORTED_RESEARCH_PATH=native remoted or paired userspace USB RemoteXPC", file=sys.stderr)
    print("UNSUPPORTED_BYPASS_REQUIRED=NO; stopped at the authorization boundary", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
