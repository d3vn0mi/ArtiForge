"""Tests for Linux auditd channel — model, generators, exporters."""

import pytest
from datetime import datetime, timezone
from artiforge.core.models import Host, User


def test_host_platform_defaults_to_windows():
    h = Host(name="WIN-WS1", ip="10.10.10.10", fqdn="WIN-WS1.lab.local")
    assert h.platform == "windows"


def test_host_platform_linux():
    h = Host(name="LNX-WEB1", ip="10.10.10.50", fqdn="lnx-web1.lab.local",
             platform="linux", os="Ubuntu 22.04 LTS")
    assert h.platform == "linux"
    assert h.os == "Ubuntu 22.04 LTS"


def test_existing_host_backward_compat():
    h = Host(name="WIN-WS1", ip="10.10.10.10", fqdn="WIN-WS1.lab.local",
             os="Windows 10 22H2", sid_prefix="S-1-5-21-111-222-333")
    assert h.platform == "windows"
    assert h.user_sid(1001) == "S-1-5-21-111-222-333-1001"


def test_linux_host_with_users():
    h = Host(name="LNX-WEB1", ip="10.10.10.50", fqdn="lnx-web1.lab.local",
             platform="linux", os="Ubuntu 22.04 LTS",
             users=[User(username="www-data", domain="lnx-web1", rid=33)])
    assert h.users[0].username == "www-data"
    assert h.users[0].rid == 33
