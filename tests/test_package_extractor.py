from dockaudit.image_analysis.package_extractor import PackageExtractor


class DummyImage:
    def __init__(self, id_value, tags=None):
        self.id = id_value
        self.tags = tags or []


def make_extractor():
    return PackageExtractor(client=None)


# ------------------------------------------------------------------
# Static parsers
# ------------------------------------------------------------------

DPKG_STATUS_SAMPLE = """\
Package: bash
Status: install ok installed
Version: 5.1-2
Description: GNU Bourne Again SHell
 multi-line continuation

Package: coreutils
Status: install ok installed
Version: 8.32-4

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0-1
"""

APK_INSTALLED_SAMPLE = """\
C:Q1abcdef
P:musl
V:1.2.4-r2
A:x86_64

C:Q2ghijkl
P:busybox
V:1.36.1-r5
"""


def test_parse_dpkg_status_skips_not_installed():
    packages = make_extractor()._parse_dpkg_status(DPKG_STATUS_SAMPLE)

    assert len(packages) == 2
    assert packages[0] == {
        "name": "bash",
        "version": "5.1-2",
        "type": "library",
        "package_manager": "dpkg"
    }
    assert packages[1]["name"] == "coreutils"


def test_parse_apk_installed():
    packages = make_extractor()._parse_apk_installed(APK_INSTALLED_SAMPLE)

    assert len(packages) == 2
    assert packages[0]["name"] == "musl"
    assert packages[0]["version"] == "1.2.4-r2"
    assert packages[0]["package_manager"] == "apk"


def test_parse_runtime_output_uses_manager_marker():
    output = "#MGR rpm\nopenssl 3.0.7-1\nzlib 1.2.13-2\n"
    packages = make_extractor()._parse_runtime_output(output)

    assert len(packages) == 2
    assert packages[0]["package_manager"] == "rpm"
    assert packages[0]["name"] == "openssl"


# ------------------------------------------------------------------
# extract() flow
# ------------------------------------------------------------------

def test_extract_returns_static_packages(monkeypatch):
    extractor = make_extractor()
    fake_packages = [{"name": "bash", "version": "5.1-2", "type": "library", "package_manager": "dpkg"}]
    monkeypatch.setattr(extractor, "_extract_static", lambda ref, timeout: (fake_packages, False))

    packages, status = extractor.extract(DummyImage("sha256abc", tags=["debian:12"]))

    assert status == "ok"
    assert packages == fake_packages


def test_extract_no_package_manager(monkeypatch):
    extractor = make_extractor()
    monkeypatch.setattr(extractor, "_extract_static", lambda ref, timeout: ([], False))

    packages, status = extractor.extract(DummyImage("sha256abc"))

    assert packages == []
    assert status == "no package manager found"


def test_extract_falls_back_to_runtime_for_rpm(monkeypatch):
    extractor = make_extractor()
    fake_packages = [{"name": "openssl", "version": "3.0.7-1", "type": "library", "package_manager": "rpm"}]
    monkeypatch.setattr(extractor, "_extract_static", lambda ref, timeout: ([], True))
    monkeypatch.setattr(extractor, "_extract_runtime", lambda ref, timeout: (fake_packages, "ok"))

    packages, status = extractor.extract(DummyImage("sha256abc"))

    assert status == "ok"
    assert packages == fake_packages


def test_extract_falls_back_when_static_fails(monkeypatch):
    extractor = make_extractor()

    def broken_static(ref, timeout):
        raise Exception("docker save failed")

    monkeypatch.setattr(extractor, "_extract_static", broken_static)
    monkeypatch.setattr(extractor, "_extract_runtime", lambda ref, timeout: ([], "no output"))

    packages, status = extractor.extract(DummyImage("sha256abc"))

    assert packages == []
    assert status == "no output"
