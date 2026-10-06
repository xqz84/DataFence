"""Isolated, pinned UCI business-data import; never security events or LLM input.

Only this official archive is downloadable. The SQLite catalogue stores aggregate
metadata, not personal rows. ZIP members are inspected in memory, never extracted.
"""

import asyncio
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sqlite3
import stat
from uuid import uuid4
import zipfile

import httpx


DATASET_ID = "uci-bank-marketing"
SOURCE_URL = "https://archive.ics.uci.edu/dataset/222/bank+marketing"
DOWNLOAD_URL = "https://archive.ics.uci.edu/static/public/222/bank%2Bmarketing.zip"
EXPECTED_SHA256 = "e0bf5f5de5b846e2f18e9d90606637267d46dfa260e0f17bb12e605db5efbeb4"
MAX_DOWNLOAD_BYTES = 100_000_000
MAX_MEMBER_BYTES = 16_000_000
MAX_EXPANDED_BYTES = 24_000_000
MAX_MEMBERS = 32
MAX_ROWS = 100_000
MAX_LINE_BYTES = 4096
COLUMNS = ("age", "job", "marital", "education", "default", "balance", "housing", "loan",
           "contact", "day", "month", "duration", "campaign", "pdays", "previous", "poutcome", "y")
INTEGER_RANGES = {"age": (0, 120), "balance": (-1_000_000_000, 1_000_000_000), "day": (1, 31),
                  "duration": (0, 1_000_000), "campaign": (1, 1_000_000), "pdays": (-1, 1_000_000),
                  "previous": (0, 1_000_000)}
CATEGORIES = {
    "job": {"admin.", "unknown", "unemployed", "management", "housemaid", "entrepreneur", "student",
            "blue-collar", "self-employed", "retired", "technician", "services"},
    "marital": {"married", "divorced", "single"}, "education": {"unknown", "secondary", "primary", "tertiary"},
    "default": {"yes", "no"}, "housing": {"yes", "no"}, "loan": {"yes", "no"},
    "contact": {"unknown", "telephone", "cellular"},
    "month": {"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"},
    "poutcome": {"unknown", "other", "failure", "success"}, "y": {"yes", "no"},
}


class PublicDataError(ValueError):
    """Fixed operational diagnostics without source rows or network response bodies."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded(path: Path, limit: int) -> bytes:
    if path.stat().st_size > limit:
        raise PublicDataError("file_size_limit")
    with path.open("rb") as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise PublicDataError("file_size_limit")
    return value


async def _download() -> bytes:
    """Fixed HTTPS origin, no redirect/proxy/retry, bounded body and wall time."""
    try:
        async with asyncio.timeout(45):
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                         timeout=httpx.Timeout(20, connect=5),
                                         headers={"Accept-Encoding": "identity"}) as client:
                async with client.stream("GET", DOWNLOAD_URL) as response:
                    if response.status_code != 200:
                        raise PublicDataError("source_http_error")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise PublicDataError("unexpected_content_encoding")
                    size = response.headers.get("content-length")
                    if size is not None and (not size.isdecimal() or int(size) > MAX_DOWNLOAD_BYTES):
                        raise PublicDataError("download_size_limit")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > MAX_DOWNLOAD_BYTES:
                            raise PublicDataError("download_size_limit")
                        body.extend(chunk)
                        await asyncio.sleep(0)
                    return bytes(body)
    except (httpx.HTTPError, TimeoutError) as exc:
        raise PublicDataError("source_unavailable") from exc


def _zip_member(data: bytes, name: str) -> bytes:
    """Validate all member metadata; stream only the selected member into memory."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_MEMBERS or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES:
                raise PublicDataError("archive_resource_limit")
            seen = set()
            for item in members:
                original = item.orig_filename  # ZipInfo normalizes Windows separators on read.
                path = PurePosixPath(item.filename)
                raw_parts = item.filename.rstrip("/").split("/")
                mode = item.external_attr >> 16
                if (not item.filename or path.is_absolute() or "\\" in original or ":" in original
                        or "\x00" in original or any(part in {"", ".", ".."} for part in raw_parts)
                        or item.filename.casefold() in seen):
                    raise PublicDataError("unsafe_archive_path")
                seen.add(item.filename.casefold())
                if stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise PublicDataError("unsupported_archive_entry")
                if item.flag_bits & 1 or item.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise PublicDataError("unsupported_archive_encoding")
                if (item.file_size > MAX_MEMBER_BYTES or item.file_size < 0
                        or item.file_size > max(1, item.compress_size) * 200):
                    raise PublicDataError("archive_resource_limit")
            member = archive.getinfo(name)
            if member.is_dir():
                raise PublicDataError("missing_data_member")
            with archive.open(member) as handle:
                content = handle.read(MAX_MEMBER_BYTES + 1)
            if len(content) > MAX_MEMBER_BYTES or len(content) != member.file_size:
                raise PublicDataError("archive_resource_limit")
            return content
    except (zipfile.BadZipFile, KeyError, RuntimeError, EOFError) as exc:
        raise PublicDataError("invalid_source_archive") from exc


def _inspect_archive(data: bytes) -> dict:
    content = _zip_member(_zip_member(data, "bank.zip"), "bank-full.csv")
    if any(len(line) > MAX_LINE_BYTES for line in content.splitlines()):
        raise PublicDataError("csv_line_limit")
    try:
        reader = csv.reader(io.StringIO(content.decode("utf-8-sig"), newline=""), delimiter=";", strict=True)
        if tuple(next(reader, ())) != COLUMNS:
            raise PublicDataError("unexpected_csv_schema")
        total = valid = duplicates = 0
        missing, unknown, invalid_reasons, labels = Counter(), Counter(), Counter(), Counter()
        seen = set()
        for values in reader:
            total += 1
            if total > MAX_ROWS:
                raise PublicDataError("csv_row_limit")
            if len(values) != len(COLUMNS) or any(len(value) > 128 for value in values):
                invalid_reasons["column_count_or_field_length"] += 1
                continue
            fingerprint = _sha(json.dumps(values, separators=(",", ":")).encode())
            duplicates += fingerprint in seen
            seen.add(fingerprint)
            bad = False
            for column, value in zip(COLUMNS, values, strict=True):
                if value == "":
                    missing[column] += 1
                    invalid_reasons["empty_cell"] += 1
                    bad = True
                elif column in INTEGER_RANGES:
                    low, high = INTEGER_RANGES[column]
                    try:
                        number = int(value)
                        if str(number) != value or not low <= number <= high:
                            raise ValueError()
                    except ValueError:
                        invalid_reasons["invalid_integer_or_range"] += 1
                        bad = True
                elif value not in CATEGORIES[column]:
                    invalid_reasons["unexpected_category"] += 1
                    bad = True
                if value == "unknown":
                    unknown[column] += 1
            if not bad:
                valid += 1
                labels[values[-1]] += 1
    except (UnicodeError, csv.Error) as exc:
        raise PublicDataError("invalid_csv_encoding_or_structure") from exc
    if not total:
        raise PublicDataError("empty_source_dataset")
    return {"row_count": total, "column_count": len(COLUMNS), "csv_sha256": _sha(content),
            "csv_bytes": len(content), "columns": list(COLUMNS),
            "quality": {"status": "passed" if valid == total else "failed", "valid_rows": valid,
                        "invalid_rows": total - valid, "duplicate_rows": duplicates,
                        "unique_rows": len(seen), "missing_cells": sum(missing.values()),
                        "missing_by_column": dict(missing), "unknown_cells": sum(unknown.values()),
                        "unknown_by_column": dict(unknown), "invalid_reason_counts": dict(invalid_reasons),
                        "unknown_is_missing": False,
                        "note": "unknown为源数据显式未知类别；完整重复行保留，不代表同一客户。"},
            "business_target": {"column": "y", "meaning": "是否订阅定期存款", "counts": dict(labels),
                                "is_security_label": False}}


def _atomic_write(path: Path, content: bytes):
    temporary = path.with_name("." + path.name + "." + uuid4().hex + ".tmp")
    try:
        temporary.write_bytes(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def import_bank_marketing(directory: Path, archive_path: Path | None = None) -> dict:
    """Import/cache the pinned official archive. Optional local file must match pin.

    Explicit operator/CLI action only. Existing verified imports need no network.
    ``directory`` is the independent runtime/public-data root, not runtime itself.
    """
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    folder = directory / DATASET_ID
    if folder.is_symlink() or (folder.exists() and folder.resolve().parent != directory):
        raise PublicDataError("unsafe_dataset_directory")
    folder.mkdir(exist_ok=True)
    source = folder / "source.zip"
    if source.is_symlink():
        raise PublicDataError("unsafe_source_file")
    if archive_path is not None:
        data = _read_bounded(Path(archive_path), MAX_DOWNLOAD_BYTES)
    elif source.is_file():
        data = _read_bounded(source, MAX_DOWNLOAD_BYTES)
    else:
        data = asyncio.run(_download())
    if _sha(data) != EXPECTED_SHA256:
        raise PublicDataError("source_checksum_mismatch")
    inspected = _inspect_archive(data)
    if inspected["quality"]["invalid_rows"]:
        raise PublicDataError("source_quality_failed")
    imported_at = datetime.now(timezone.utc).isoformat()
    existing = list_datasets(directory)
    previous = next((item for item in existing if item["id"] == DATASET_ID), None)
    if previous and previous["sha256"] == EXPECTED_SHA256:
        imported_at = previous["imported_at"]
    summary = {"id": DATASET_ID, "name": "UCI Bank Marketing（bank-full）", "status": "imported",
               "source_url": SOURCE_URL, "download_url": DOWNLOAD_URL,
               "license": {"id": "CC-BY-4.0", "url": "https://creativecommons.org/licenses/by/4.0/",
                           "attribution": "Moro, S., Rita, P., & Cortez, P. (2014). Bank Marketing. UCI Machine Learning Repository. https://doi.org/10.24432/C5K306"},
               "origin": "public_bank_business_data", "synthetic": False,
               "imported_at": imported_at, "source_verified_at": "2026-09-19", "sha256": EXPECTED_SHA256,
               "download_bytes": len(data), "source_member": "bank.zip!bank-full.csv",
               "checksum_basis": "operator-pinned official HTTPS download; not a publisher signature",
               "source_integrity": True, "security_labels_available": False,
               "used_for_detection_training": False, "llm_access": False, **inspected,
               "modifications": "原始压缩包保留；只生成字段与质量聚合，未修补、拼接或去重源记录。",
               "limitations": ["葡萄牙银行历史营销业务数据，不是工商银行数据或本项目合成客户。",
                               "y表示定期存款订阅，不是攻击标签；不能据此验证DLP或内部威胁检测效果。",
                               "含个人层面人口统计与金融属性；仅提供聚合元数据，不进入业务事件、检测训练或云模型。",
                               "记录数不是去重客户数；unknown类别与空值分开统计。"]}
    if not source.exists():
        _atomic_write(source, data)
    elif _sha(_read_bounded(source, MAX_DOWNLOAD_BYTES)) != EXPECTED_SHA256:
        raise PublicDataError("cached_source_checksum_mismatch")
    serialized = json.dumps(summary, ensure_ascii=False, sort_keys=True, allow_nan=False)
    _atomic_write(folder / "manifest.json", (serialized + "\n").encode())
    with sqlite3.connect(directory / "catalog.sqlite3", timeout=10) as db:
        db.execute("CREATE TABLE IF NOT EXISTS datasets (id TEXT PRIMARY KEY, summary_json TEXT NOT NULL)")
        db.execute("INSERT INTO datasets VALUES (?,?) ON CONFLICT(id) DO UPDATE SET summary_json=excluded.summary_json",
                   (DATASET_ID, serialized))
    return summary


def list_datasets(directory: Path) -> list[dict]:
    """Read-only aggregate catalogue; no row endpoint and no network/LLM access."""
    directory = Path(directory).resolve()
    database = directory / "catalog.sqlite3"
    if not database.exists():
        return []
    if database.is_symlink() or database.stat().st_size > 4_000_000:
        raise PublicDataError("invalid_catalogue")
    try:
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1) as db:
            db.execute("PRAGMA query_only=ON")
            rows = db.execute("SELECT id,summary_json FROM datasets ORDER BY id LIMIT 20").fetchall()
        result = []
        for dataset_id, serialized in rows:
            if dataset_id != DATASET_ID or len(serialized) > 100_000:
                raise PublicDataError("invalid_catalogue_entry")
            summary = json.loads(serialized)
            source = directory / DATASET_ID / "source.zip"
            valid = (not source.is_symlink() and source.is_file()
                     and _sha(_read_bounded(source, MAX_DOWNLOAD_BYTES)) == EXPECTED_SHA256
                     and summary.get("sha256") == EXPECTED_SHA256 and summary.get("id") == DATASET_ID)
            summary["source_integrity"] = valid
            summary["status"] = "imported" if valid else "integrity_failed"
            result.append(summary)
        return result
    except (sqlite3.Error, OSError, ValueError, TypeError) as exc:
        raise PublicDataError("catalogue_unavailable") from exc
