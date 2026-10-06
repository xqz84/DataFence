"""Download and inventory fixed official CERT r1 archives without extracting logs.

No detection mapping, model calls, execution of content, or security scoring.
"""

import argparse
import asyncio
import bz2
import csv
from collections import Counter
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from urllib.parse import urlsplit
from uuid import uuid4

import httpx


METADATA_URL = "https://api.figshare.com/v2/articles/12841247"
FILES = {"SEI_Insider_README.txt": 24860765, "CHECKSUMS-sha256.txt": 24857831,
         "r1.tar.bz2": 24857825, "answers.tar.bz2": 24857828}
MAX_DOWNLOAD = 100_000_000
MAX_EXPANDED = 1_000_000_000
MAX_MEMBER = 512_000_000
MAX_MEMBERS = 200
PUBLISHER_SHA256 = {
    "r1.tar.bz2": "8a70ad175df477dd5a35e8422ff236bc6a9ca76f48ae7e0d29c471c4efa52fa3",
    "answers.tar.bz2": "ed21bf921def01e97326b314f2d1fa77651a945bd31bf513095f8ac7658c9ddd",
}


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1_048_576):
            result.update(chunk)
    return result.hexdigest()


async def download(url, destination, limit, expected=None):
    if destination.is_file():
        if destination.stat().st_size > limit or expected and digest(destination) != expected:
            raise ValueError("cached_source_integrity_failed")
        return
    temporary = destination.with_name("." + destination.name + "." + uuid4().hex + ".part")
    try:
        async with asyncio.timeout(180):
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                         timeout=httpx.Timeout(25, connect=8),
                                         headers={"Accept-Encoding": "identity"}) as client:
                for attempt in range(2):
                    async with client.stream("GET", url) as response:
                        if response.status_code == 302 and attempt == 0:
                            location = response.headers.get("location", "")
                            parsed = urlsplit(location)
                            if (parsed.scheme != "https" or parsed.hostname != "s3-eu-west-1.amazonaws.com"
                                    or not parsed.path.startswith("/pstorage-cmu-348901238291901/" + urlsplit(url).path.rsplit("/", 1)[-1] + "/") or parsed.username
                                    or parsed.password or parsed.port not in {None, 443}):
                                raise ValueError("unapproved_download_redirect")
                            url = location
                            continue
                        if response.status_code != 200:
                            raise ValueError("official_source_unavailable")
                        size = response.headers.get("content-length")
                        if size is not None and (not size.isdecimal() or int(size) > limit):
                            raise ValueError("download_size_limit")
                        if response.headers.get("content-encoding", "identity").lower() != "identity":
                            raise ValueError("unsupported_http_encoding")
                        received, check = 0, hashlib.sha256()
                        with temporary.open("xb") as handle:
                            async for chunk in response.aiter_bytes():
                                received += len(chunk)
                                if received > limit:
                                    raise ValueError("download_size_limit")
                                check.update(chunk)
                                handle.write(chunk)
                                await asyncio.sleep(0)
                        if expected and check.hexdigest() != expected:
                            raise ValueError("publisher_checksum_mismatch")
                        temporary.replace(destination)
                        return
                raise ValueError("download_redirect_limit")
    finally:
        temporary.unlink(missing_ok=True)


def inventory(path):
    members, total, readmes, entry_count = [], 0, [], 0
    license_notices, label_index = [], None
    try:
        # BZ2File handles concatenated bzip2 streams in the official old archive.
        with bz2.open(path, "rb") as decompressed, tarfile.open(fileobj=decompressed, mode="r|") as archive:
            for member in archive:
                entry_count += 1
                if entry_count > MAX_MEMBERS:
                    raise ValueError("tar_resource_limit")
                parts = member.name.rstrip("/").split("/")
                if (PurePosixPath(member.name).is_absolute() or "\\" in member.name or ":" in member.name
                        or any(part in {"", ".."} for part in parts) or "\x00" in member.name):
                    raise ValueError("unsafe_tar_path")
                if member.isdir():
                    continue
                if not member.isfile() or member.issparse():
                    raise ValueError("unsupported_tar_entry")
                total += member.size
                if len(members) >= MAX_MEMBERS or member.size > MAX_MEMBER or total > MAX_EXPANDED:
                    raise ValueError("tar_resource_limit")
                if member.name in {item["name"] for item in members}:
                    raise ValueError("duplicate_tar_path")
                with archive.extractfile(member) as handle:
                    check, size, newlines, prefix, last = hashlib.sha256(), 0, 0, bytearray(), b""
                    while chunk := handle.read(1_048_576):
                        size += len(chunk)
                        if size > MAX_MEMBER or size > member.size:
                            raise ValueError("tar_resource_limit")
                        check.update(chunk)
                        newlines += chunk.count(b"\n")
                        if len(prefix) < 65536:
                            prefix.extend(chunk[:65536 - len(prefix)])
                        last = chunk[-1:]
                if size != member.size:
                    raise ValueError("truncated_tar_member")
                entry = {"name": member.name, "bytes": size, "sha256": check.hexdigest(),
                         "physical_lines": newlines + int(bool(size) and last != b"\n")}
                if member.name.lower().endswith(".csv"):
                    header = bytes(prefix).split(b"\n", 1)[0].decode("utf-8-sig", errors="strict")
                    columns = next(csv.reader([header]))
                    # Headers are metadata only; never include sample record values.
                    if len(columns) <= 40 and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9 _.-]{0,60}", c) for c in columns):
                        entry["columns"] = columns
                    else:
                        entry["columns"] = None
                if "readme" in member.name.lower() and size <= 65536:
                    readmes.append({"name": member.name, "text": prefix.decode("utf-8", errors="replace")})
                if member.name.lower().endswith("license.txt") and size <= 65536:
                    license_text = prefix.decode("cp1252")
                    license_notices.append({"member": member.name, "sha256": check.hexdigest(),
                                            "holder": "ExactData, LLC" if "ExactData, LLC" in license_text else "unverified",
                                            "restriction_text_detected": "prohibited from publishing" in license_text})
                if member.name == "answers/insiders.csv" and size <= 65536:
                    records = csv.reader(io.StringIO(prefix.decode("utf-8-sig")))
                    header = next(records)
                    if header != ["dataset", "scenario", "details", "user", "start", "end"]:
                        raise ValueError("unexpected_label_index_schema")
                    counts = Counter()
                    for row in records:
                        if len(row) != 6 or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", row[0]):
                            raise ValueError("unexpected_label_index_row")
                        counts[row[0]] += 1
                    label_index = {"member": member.name, "header": header, "release_counts": dict(counts),
                                   "r1_label_rows": sum(n for k, n in counts.items() if k in {"1", "1.0"})}
                members.append(entry)
        return {"complete": True, "member_count": len(members), "expanded_bytes": total,
                "members": members, "readmes": readmes, "license_notices": license_notices, "label_index": label_index}
    except (ValueError, tarfile.TarError, OSError, EOFError, UnicodeError) as exc:
        return {"complete": False, "member_count": len(members), "expanded_bytes_inspected": sum(m["bytes"] for m in members),
                "reason": str(exc) if isinstance(exc, ValueError) else type(exc).__name__,
                "members": members, "readmes": readmes, "license_notices": license_notices, "label_index": label_index}


async def prepare(directory):
    await download(METADATA_URL, directory / "source-metadata.json", 2_000_000)
    metadata = json.loads((directory / "source-metadata.json").read_text(encoding="utf-8"))
    if metadata.get("license", {}).get("name") != "CC BY 4.0":
        raise ValueError("source_license_changed")
    indexed = {f["name"]: f for f in metadata["files"]}
    if sum(indexed[name]["size"] for name in FILES) > MAX_DOWNLOAD:
        raise ValueError("total_download_limit")
    for name, ident in FILES.items():
        expected_url = "https://ndownloader.figshare.com/files/" + str(ident)
        if indexed[name]["download_url"] != expected_url:
            raise ValueError("official_file_identity_changed")
        expected = None
        if name.endswith(".tar.bz2"):
            checksums = (directory / "CHECKSUMS-sha256.txt").read_text(encoding="utf-8")
            found = re.findall(r"^([a-fA-F0-9]{64})\s+\*?" + re.escape(name) + r"\s*$", checksums, re.MULTILINE)
            if len(found) != 1:
                raise ValueError("publisher_checksum_missing")
            expected = found[0].lower()
            if expected != PUBLISHER_SHA256[name]:
                raise ValueError("publisher_version_changed")
        await download(expected_url, directory / name, min(MAX_DOWNLOAD, indexed[name]["size"]), expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("runtime/public-data/cert-r1"))
    parser.add_argument("--download", action="store_true", help="Explicit bounded official download; otherwise offline inventory only")
    args = parser.parse_args()
    root = args.directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    if any((root / name).is_symlink() for name in (*FILES, "source-metadata.json")):
        raise ValueError("unsafe_source_file")
    if args.download:
        asyncio.run(prepare(root))
    for name, expected in PUBLISHER_SHA256.items():
        if (root / name).stat().st_size > MAX_DOWNLOAD or digest(root / name) != expected:
            raise ValueError("publisher_checksum_mismatch")
    summary = {"created_at": datetime.now(timezone.utc).isoformat(), "source_url": "https://www.sei.cmu.edu/library/insider-threat-test-dataset/",
               "metadata_url": METADATA_URL, "repository_license": "CC-BY-4.0",
               "license_status": "repository_and_embedded_terms_need_clarification", "synthetic": True,
               "download_limit_bytes": MAX_DOWNLOAD, "max_member_bytes": MAX_MEMBER,
               "max_expanded_bytes_per_archive": MAX_EXPANDED, "max_members_per_archive": MAX_MEMBERS,
               "source_files": {name: {"bytes": (root / name).stat().st_size, "sha256": digest(root / name)} for name in FILES},
               "logs": inventory(root / "r1.tar.bz2"), "answers": inventory(root / "answers.tar.bz2"),
               "used_for_training": False, "used_for_evaluation": False, "sent_to_llm": False,
               "note": "Inventory only; physical lines are not independently validated CSV records. No extraction or label mapping."}
    (root / "inventory.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if summary["answers"]["label_index"]:
        (root / "label-index-summary.json").write_text(json.dumps(summary["answers"]["label_index"], indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"logs_complete": summary["logs"]["complete"], "answers_complete": summary["answers"]["complete"],
                      "logs_members": summary["logs"]["member_count"], "answers_members": summary["answers"]["member_count"],
                      "source_files": summary["source_files"]}, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
