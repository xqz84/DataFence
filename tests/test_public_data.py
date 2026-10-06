import asyncio
import gzip
import hashlib
import io
import importlib.util
import json
from pathlib import Path
import sqlite3
import stat
import tarfile
import zipfile

import pytest
import httpx

from datafence import public_data as data


ROW = ["34", "technician", "single", "secondary", "no", "120", "yes", "no",
       "unknown", "12", "may", "60", "1", "-1", "0", "unknown", "no"]


def zipped(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files:
            archive.writestr(name, content)
    return stream.getvalue()


def archive(rows=None):
    rows = [ROW] if rows is None else rows
    csv = ";".join(data.COLUMNS) + "\n" + "\n".join(";".join(row) for row in rows) + "\n"
    return zipped([("bank.zip", zipped([("bank-full.csv", csv)]))])


def pinned_file(tmp_path, monkeypatch, content=None):
    content = archive() if content is None else content
    path = tmp_path / "fixture.zip"
    path.write_bytes(content)
    monkeypatch.setattr(data, "EXPECTED_SHA256", hashlib.sha256(content).hexdigest())
    return path


def test_import_is_reentrant_offline_and_catalogue_contains_only_aggregates(tmp_path, monkeypatch):
    path = pinned_file(tmp_path, monkeypatch)
    destination = tmp_path / "public-data"
    first = data.import_bank_marketing(destination, path)

    async def forbidden():
        pytest.fail("cached import must not contact network")

    monkeypatch.setattr(data, "_download", forbidden)
    assert data.import_bank_marketing(destination) == first
    assert data.list_datasets(destination) == [first]
    with sqlite3.connect(destination / "catalog.sqlite3") as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("datasets",)]
    assert first["business_target"]["is_security_label"] is False
    assert first["security_labels_available"] is False
    assert first["used_for_detection_training"] is False and first["llm_access"] is False
    assert "rows" not in first and first["row_count"] == 1
    assert not list(destination.rglob("*.csv"))  # No extraction or row-serving store.


def test_pinned_checksum_rejects_replaced_source_before_parsing(tmp_path, monkeypatch):
    source = pinned_file(tmp_path, monkeypatch)
    source.write_bytes(archive([ROW, ROW]))
    with pytest.raises(data.PublicDataError, match="source_checksum_mismatch"):
        data.import_bank_marketing(tmp_path / "public-data", source)


@pytest.mark.parametrize("name", ["../outside.csv", "/absolute.csv", "C:/outside.csv", "folder\\outside.csv",
                                  "name:stream", "folder/../outside.csv"])
def test_zip_traversal_rejected_even_for_unselected_member(name):
    value = zipped([("bank.zip", b"irrelevant"), (name, b"payload")])
    if "\\" in name:
        # Windows ZipFile normalizes separators on write; simulate hostile bytes.
        value = value.replace(name.replace("\\", "/").encode(), name.encode())
    with pytest.raises(data.PublicDataError, match="unsafe_archive_path"):
        data._zip_member(value, "bank.zip")


def test_zip_symlink_and_case_collisions_rejected():
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(data.PublicDataError, match="unsupported_archive_entry"):
        data._zip_member(zipped([("bank.zip", b"a"), (link, "outside")]), "bank.zip")
    with pytest.raises(data.PublicDataError, match="unsafe_archive_path"):
        data._zip_member(zipped([("bank.zip", b"a"), ("BANK.ZIP", b"b")]), "bank.zip")


def test_archive_row_and_file_limits(monkeypatch):
    value = archive([ROW, ROW])
    monkeypatch.setattr(data, "MAX_ROWS", 1)
    with pytest.raises(data.PublicDataError, match="csv_row_limit"):
        data._inspect_archive(value)
    monkeypatch.setattr(data, "MAX_MEMBER_BYTES", 1)
    with pytest.raises(data.PublicDataError, match="archive_resource_limit"):
        data._inspect_archive(value)


def test_quality_counts_unknown_duplicate_invalid_and_business_target_separately():
    invalid = ROW.copy()
    invalid[0], invalid[1], invalid[-1] = "", "unexpected", "ATTACK"
    result = data._inspect_archive(archive([ROW, ROW, invalid]))
    assert result["row_count"] == 3
    assert result["quality"]["valid_rows"] == 2 and result["quality"]["invalid_rows"] == 1
    assert result["quality"]["duplicate_rows"] == 1
    assert result["quality"]["missing_cells"] == 1 and result["quality"]["unknown_cells"] == 6
    assert result["business_target"]["counts"] == {"no": 2}


def test_listing_is_read_only_reports_tampering_and_does_not_expose_source_rows(tmp_path, monkeypatch):
    path = pinned_file(tmp_path, monkeypatch)
    destination = tmp_path / "public-data"
    data.import_bank_marketing(destination, path)
    catalogue = destination / "catalog.sqlite3"
    previous = catalogue.read_bytes()
    (destination / data.DATASET_ID / "source.zip").write_bytes(b"tampered")
    result = data.list_datasets(destination)
    assert result[0]["source_integrity"] is False and result[0]["status"] == "integrity_failed"
    assert catalogue.read_bytes() == previous
    assert json.dumps(ROW) not in json.dumps(result)


def test_listing_missing_catalogue_does_not_create_files(tmp_path):
    path = tmp_path / "missing"
    assert data.list_datasets(path) == [] and not path.exists()


def test_invalid_schema_never_becomes_imported_catalogue(tmp_path, monkeypatch):
    invalid = ROW.copy()
    invalid[-1] = "ATTACK"
    path = pinned_file(tmp_path, monkeypatch, archive([invalid]))
    with pytest.raises(data.PublicDataError, match="source_quality_failed"):
        data.import_bank_marketing(tmp_path / "public-data", path)
    assert not (tmp_path / "public-data" / "catalog.sqlite3").exists()


@pytest.mark.parametrize("status,headers,reason", [(302, {"location": "https://untrusted.example/data"}, "source_http_error"),
                                                 (200, {"content-length": "100000001"}, "download_size_limit"),
                                                 (200, {"content-encoding": "gzip"}, "unexpected_content_encoding")])
def test_network_source_rejects_redirect_oversize_and_compressed_body(monkeypatch, status, headers, reason):
    original = httpx.AsyncClient

    def respond(request):
        assert str(request.url) == data.DOWNLOAD_URL
        body = gzip.compress(b"small") if headers.get("content-encoding") == "gzip" else b"small"
        return httpx.Response(status, headers=headers, content=body)

    def client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return original(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(data.httpx, "AsyncClient", client)
    with pytest.raises(data.PublicDataError, match=reason):
        asyncio.run(data._download())


def cert_module():
    spec = importlib.util.spec_from_file_location("cert_inspector_test", Path(__file__).parents[1] / "scripts" / "inspect_cert.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tar_fixture(path, files):
    with tarfile.open(path, "w:bz2") as archive:
        for name, content in files:
            item = tarfile.TarInfo(name)
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))


def test_cert_inspection_rejects_traversal_and_keeps_no_extracted_rows(tmp_path):
    inspector = cert_module()
    path = tmp_path / "sample.tar.bz2"
    tar_fixture(path, [("../outside.csv", b"id,date\n")])
    result = inspector.inventory(path)
    assert not result["complete"] and result["reason"] == "unsafe_tar_path"
    assert list(tmp_path.iterdir()) == [path]


def test_cert_inventory_is_partial_when_member_budget_reached(tmp_path, monkeypatch):
    inspector = cert_module()
    monkeypatch.setattr(inspector, "MAX_MEMBERS", 1)
    path = tmp_path / "sample.tar.bz2"
    tar_fixture(path, [("first.txt", b"ok"), ("second.txt", b"later")])
    result = inspector.inventory(path)
    assert not result["complete"] and result["reason"] == "tar_resource_limit"
    assert result["member_count"] == 1


def test_cert_master_label_summary_does_not_treat_r1_as_normal_or_expose_users(tmp_path):
    inspector = cert_module()
    path = tmp_path / "answers.tar.bz2"
    content = b"dataset,scenario,details,user,start,end\n4.2,1,file,DO_NOT_EXPOSE,begin,end\n"
    tar_fixture(path, [("answers/insiders.csv", content)])
    result = inspector.inventory(path)
    assert result["complete"] and result["label_index"]["r1_label_rows"] == 0
    assert result["label_index"]["release_counts"] == {"4.2": 1}
    assert "DO_NOT_EXPOSE" not in json.dumps(result)
