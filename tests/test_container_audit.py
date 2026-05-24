import pytest

from dockaudit.container_audit.container_scanner import ContainerAudit


class DummyContainer:
    def __init__(self, name, attrs):
        self.name = name
        self.attrs = attrs


class DummyContainers:
    def __init__(self, items):
        self._items = items

    def list(self, all=True):
        return self._items


class DummyDocker:
    def __init__(self, containers):
        self.containers = DummyContainers(containers)


class DummyDockerModule:
    def __init__(self, docker_client):
        self._client = docker_client

    def from_env(self):
        return self._client


def test_container_audit_no_containers(monkeypatch):
    audit = ContainerAudit()
    dummy = DummyDocker([])
    monkeypatch.setattr("dockaudit.container_audit.container_scanner.docker.from_env", lambda: dummy)

    findings = audit.run()
    assert len(findings) == 1
    assert findings[0]["id"] == "CONT-001"


def test_container_audit_privileged(monkeypatch):
    attrs = {
        "HostConfig": {"Privileged": True, "NetworkMode": "bridge", "CapAdd": []},
        "Mounts": []
    }
    container = DummyContainer("test", attrs)
    audit = ContainerAudit()
    dummy = DummyDocker([container])
    monkeypatch.setattr("dockaudit.container_audit.container_scanner.docker.from_env", lambda: dummy)

    findings = audit.run()
    assert any(item["id"] == "CONT-002" for item in findings)


def test_container_audit_docker_failure(monkeypatch):
    audit = ContainerAudit()

    class FakeError(Exception):
        pass

    def raise_error():
        raise FakeError("failed")

    monkeypatch.setattr("dockaudit.container_audit.container_scanner.docker.from_env", raise_error)
    findings = audit.run()
    assert findings[0]["severity"] == "critical"
