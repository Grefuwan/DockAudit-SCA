from dockaudit.image_analysis.package_extractor import PackageExtractor


class DummyContainers:
    def __init__(self, output):
        self.output = output

    def run(self, image_id, command, remove, stdout, stderr, tty, **kwargs):
        return self.output


class DummyClient:
    def __init__(self, output):
        self.containers = DummyContainers(output)


class DummyImage:
    def __init__(self, id_value):
        self.id = id_value


def test_package_extractor_parses_dpkg_output():
    output = b"bash 5.1-2\ncoreutils 8.32-4\n"
    extractor = PackageExtractor(DummyClient(output))
    packages, status = extractor.extract(DummyImage("sha256abc"))

    assert status == "ok"
    assert len(packages) == 2
    assert packages[0]["name"] == "bash"
    assert packages[0]["version"] == "5.1-2"


def test_package_extractor_no_package_manager():
    output = b"NO_PKG_MGR\n"
    extractor = PackageExtractor(DummyClient(output))
    packages, status = extractor.extract(DummyImage("sha256abc"))

    assert packages == []
    assert status == "no package manager found"


def test_package_extractor_handles_errors():
    class BrokenContainers:
        def run(self, image_id, command, remove, stdout, stderr, tty, **kwargs):
            raise RuntimeError("container failed")

    class BrokenClient:
        def __init__(self):
            self.containers = BrokenContainers()

    extractor = PackageExtractor(BrokenClient())
    packages, status = extractor.extract(DummyImage("sha256abc"))

    assert packages == []
    assert "container failed" in status
