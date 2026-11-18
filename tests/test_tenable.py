"""tenable_scan_retrieval.py against a fake `requests`. No network, no tenant."""

import datetime
import importlib
import os
import sys

import pytest
import requests

import tenable_scan_retrieval as tsr


class FakeResponse:
    def __init__(self, status=200, json_data=None, chunks=(), headers=None):
        self.status_code = status
        self._json = json_data
        self._chunks = list(chunks)
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json

    def iter_content(self, chunk_size=None):
        for c in self._chunks:
            if isinstance(c, Exception):
                raise c
            yield c


class Recorder:
    """Stands in for requests.get/post; returns queued responses and records the kwargs."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


@pytest.fixture(autouse=True)
def fast(monkeypatch):
    monkeypatch.setattr(tsr.time, "sleep", lambda s: None)
    monkeypatch.delenv("TENABLE_URL", raising=False)


def patch_http(monkeypatch, get=(), post=()):
    g, p = Recorder(get), Recorder(post)
    monkeypatch.setattr(tsr.requests, "get", g)
    monkeypatch.setattr(tsr.requests, "post", p)
    return g, p


# ---- import side effects (audit L2) ----

def test_importing_the_module_creates_no_directories_and_asks_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("prompted on import"))
    importlib.reload(tsr)
    assert os.listdir(tmp_path) == []


# ---- timeouts (audit M10) ----

def test_every_request_carries_a_timeout(monkeypatch, tmp_path):
    get, post = patch_http(
        monkeypatch,
        get=[FakeResponse(json_data={"scans": [{"id": 1, "name": "s"}]}),
             FakeResponse(json_data={"status": "ready"}),
             FakeResponse(chunks=[b"abc"], headers={"Content-Length": "3"})],
        post=[FakeResponse(json_data={"file": 99})])
    h = {"X-ApiKeys": "k"}
    assert tsr.get_all_scans(h)
    assert tsr.initiate_export(1, h) == 99
    assert tsr.wait_for_export(1, 99, h)
    assert tsr.download_scan(1, "s", 99, h, str(tmp_path))
    for url, kwargs in get.calls + post.calls:
        assert kwargs.get("timeout") == tsr.TIMEOUT, url
    assert tsr.TIMEOUT[0] and tsr.TIMEOUT[1]


# ---- credentials (audit M11) ----

def test_credentials_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AK")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SK")
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("prompted"))
    monkeypatch.setattr(tsr.getpass, "getpass", lambda *a: pytest.fail("prompted"))
    assert tsr.get_api_credentials() == ("AK", "SK")


def test_secret_key_is_read_with_getpass_not_input(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    prompts = []
    monkeypatch.setattr("builtins.input", lambda p="": prompts.append(p) or "AK")
    monkeypatch.setattr(tsr.getpass, "getpass", lambda p="": "SK")
    assert tsr.get_api_credentials() == ("AK", "SK")
    assert not any("Secret" in p for p in prompts)


def test_missing_credentials_exit(monkeypatch):
    monkeypatch.delenv("TENABLE_ACCESS_KEY", raising=False)
    monkeypatch.delenv("TENABLE_SECRET_KEY", raising=False)
    monkeypatch.setattr("builtins.input", lambda p="": "")
    with pytest.raises(SystemExit):
        tsr.get_api_credentials()


# ---- file names and folders (audit L1, L11) ----

@pytest.mark.parametrize("raw", ["a\\b..\\..\\x:y/z", "..", "../../etc/passwd", "C:\\Windows\\x", "a\x00b"])
def test_sanitize_filename_never_yields_a_path(raw):
    out = tsr.sanitize_filename(raw)
    assert out and out not in (".", "..")
    assert not any(ch in out for ch in '\\/:*?"<>|\x00')


def test_sanitize_filename_reserved_names_and_trailing_dots():
    assert tsr.sanitize_filename("CON") == "_CON"
    assert tsr.sanitize_filename("nul.txt") == "_nul.txt"
    assert tsr.sanitize_filename("name. . ") == "name"
    assert tsr.sanitize_filename("") == "scan"
    assert len(tsr.sanitize_filename("x" * 500)) <= 150


def test_same_named_scans_get_different_files(tmp_path):
    a = tsr.scan_output_path(str(tmp_path), "Weekly", 1)
    b = tsr.scan_output_path(str(tmp_path), "Weekly", 2)
    assert a != b and a.endswith("Weekly-1.nessus") and b.endswith("Weekly-2.nessus")


def test_scan_output_path_stays_inside_the_folder(tmp_path):
    p = tsr.scan_output_path(str(tmp_path), "..\\..\\evil", "1/../2")
    assert os.path.dirname(os.path.abspath(p)) == os.path.abspath(str(tmp_path))


def test_year_boundary_uses_the_iso_year():
    """2027-01-01 is ISO week 53 of 2026, so it belongs under 2026."""
    path = tsr.build_output_dir(datetime.datetime(2027, 1, 1))
    assert path.replace("\\", "/") == "2026/01-January/Week-53"
    assert tsr.build_output_dir(datetime.datetime(2026, 11, 18), base="out").replace("\\", "/") == \
        "out/2026/11-November/Week-47"


# ---- API robustness (audit L12) ----

def test_scans_null_is_an_empty_list(monkeypatch):
    patch_http(monkeypatch, get=[FakeResponse(json_data={"scans": None})])
    assert tsr.get_all_scans({}) == []


def test_fetch_error_is_none_not_empty(monkeypatch):
    patch_http(monkeypatch, get=[FakeResponse(status=500)])
    assert tsr.get_all_scans({}) is None


def test_rate_limit_is_retried_with_retry_after(monkeypatch):
    sleeps = []
    monkeypatch.setattr(tsr.time, "sleep", sleeps.append)
    get, _ = patch_http(monkeypatch, get=[
        FakeResponse(status=429, headers={"Retry-After": "7"}),
        FakeResponse(json_data={"scans": [{"id": 1}]})])
    assert tsr.get_all_scans({}) == [{"id": 1}]
    assert sleeps == [7.0] and len(get.calls) == 2


def test_rate_limit_gives_up_after_the_retry_budget(monkeypatch):
    get, _ = patch_http(monkeypatch, get=[FakeResponse(status=429)] * (tsr.MAX_RATE_LIMIT_RETRIES + 1))
    assert tsr.get_all_scans({}) is None
    assert len(get.calls) == tsr.MAX_RATE_LIMIT_RETRIES + 1


def test_failed_export_status_stops_polling_early(monkeypatch):
    get, _ = patch_http(monkeypatch, get=[FakeResponse(json_data={"status": "error"})])
    assert tsr.wait_for_export(1, 2, {}) is False
    assert len(get.calls) == 1


def test_export_that_never_finishes_times_out(monkeypatch):
    get, _ = patch_http(monkeypatch, get=[FakeResponse(json_data={"status": "loading"})] * 3)
    assert tsr.wait_for_export(1, 2, {}, max_retries=3, wait_time=0) is False


def test_download_writes_part_then_renames(monkeypatch, tmp_path):
    patch_http(monkeypatch, get=[FakeResponse(chunks=[b"ab", b"cd"], headers={"Content-Length": "4"})])
    out = tsr.download_scan(5, "Scan", 9, {}, str(tmp_path / "x" / "y"))
    assert out.endswith("Scan-5.nessus")
    assert open(out, "rb").read() == b"abcd"
    assert not os.path.exists(out + ".part")


def test_interrupted_download_leaves_no_nessus_file(monkeypatch, tmp_path):
    patch_http(monkeypatch, get=[FakeResponse(
        chunks=[b"ab", requests.exceptions.ChunkedEncodingError("cut")], headers={"Content-Length": "10"})])
    assert tsr.download_scan(5, "Scan", 9, {}, str(tmp_path)) is None
    assert os.listdir(tmp_path) == []


def test_short_download_is_rejected(monkeypatch, tmp_path):
    patch_http(monkeypatch, get=[FakeResponse(chunks=[b"ab"], headers={"Content-Length": "10"})])
    assert tsr.download_scan(5, "Scan", 9, {}, str(tmp_path)) is None
    assert os.listdir(tmp_path) == []


def test_tenable_url_must_be_https(monkeypatch):
    monkeypatch.setenv("TENABLE_URL", "http://example.com")
    with pytest.raises(SystemExit):
        tsr.get_base_url()
    monkeypatch.setenv("TENABLE_URL", "https://fedcloud.tenable.com/")
    assert tsr.get_base_url() == "https://fedcloud.tenable.com"


# ---- main ----

def test_main_unattended_all(monkeypatch, tmp_path):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AK")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SK")
    monkeypatch.setattr("builtins.input", lambda *a: pytest.fail("prompted"))
    get, post = patch_http(
        monkeypatch,
        get=[FakeResponse(json_data={"scans": [{"id": 1, "name": "A"}, {"id": 2, "name": "A"}]}),
             FakeResponse(json_data={"status": "ready"}),
             FakeResponse(chunks=[b"1"], headers={"Content-Length": "1"}),
             FakeResponse(json_data={"status": "ready"}),
             FakeResponse(chunks=[b"2"], headers={"Content-Length": "1"})],
        post=[FakeResponse(json_data={"file": 10}), FakeResponse(json_data={"file": 11})])
    assert tsr.main(["--all", "--output-dir", str(tmp_path)]) == 0
    names = sorted(f for _, _, files in os.walk(tmp_path) for f in files)
    assert names == ["A-1.nessus", "A-2.nessus"]
    assert post.calls[0][1]["headers"]["X-ApiKeys"] == "accessKey=AK; secretKey=SK;"


def test_main_unknown_scan_id_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AK")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SK")
    patch_http(monkeypatch, get=[FakeResponse(json_data={"scans": [{"id": 1, "name": "A"}]})])
    assert tsr.main(["--scan-id", "5", "--output-dir", str(tmp_path)]) == 1
    assert os.listdir(tmp_path) == []


def test_main_failed_download_gives_nonzero_exit(monkeypatch, tmp_path):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "AK")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "SK")
    patch_http(monkeypatch,
               get=[FakeResponse(json_data={"scans": [{"id": 1, "name": "A"}]})],
               post=[FakeResponse(status=403)])
    assert tsr.main(["--all", "--output-dir", str(tmp_path)]) == 1
