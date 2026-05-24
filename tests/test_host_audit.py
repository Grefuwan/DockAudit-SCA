import json
import os
import subprocess

import pytest

from dockaudit.host_audit.host_scanner import HostAudit


class DummyCompletedProcess:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_check_docker_version_success(monkeypatch):
    host = HostAudit()

    def fake_run(*args, **kwargs):
        return DummyCompletedProcess(0, "Docker version 26.0.0, build abc123")

    monkeypatch.setattr(subprocess, "run", fake_run)
    host.check_docker_version()

    assert any(item["id"] == "HOST-001" for item in host.findings)


def test_check_docker_socket_permissions(monkeypatch, tmp_path):
    host = HostAudit()
    socket_path = "/var/run/docker.sock"

    monkeypatch.setattr(os.path, "exists", lambda path: path == socket_path)

    class DummyStat:
        st_mode = 0o100660

    monkeypatch.setattr(os, "stat", lambda path: DummyStat())
    host.check_docker_socket_permissions()

    assert any(item["id"] == "HOST-005" for item in host.findings)


def test_check_daemon_configuration(monkeypatch, tmp_path):
    host = HostAudit()
    daemon_path = "/etc/docker/daemon.json"
    config_data = {"live-restore": True}

    monkeypatch.setattr(os.path, "exists", lambda path: path == daemon_path)
    monkeypatch.setattr("builtins.open", lambda path, mode='r': tmp_path.joinpath("daemon.json").open(mode))
    tmp_path.joinpath("daemon.json").write_text(json.dumps(config_data))

    host.check_daemon_configuration()

    assert any(item["id"] == "HOST-008" for item in host.findings)
