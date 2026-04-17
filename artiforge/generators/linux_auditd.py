"""Linux auditd record type generators.

SYSCALL (1300), EXECVE (1309), PATH (1302), SOCKADDR (1306),
USER_AUTH (1100), USER_LOGIN (1101), CRED_ACQ (1103)
"""

from __future__ import annotations

import random
from typing import Any

from artiforge.core.models import Host, User


_ALIASES = {
    "SYSCALL": 1300, "EXECVE": 1309, "PATH": 1302, "SOCKADDR": 1306,
    "USER_AUTH": 1100, "USER_LOGIN": 1101, "CRED_ACQ": 1103,
}


def resolve_eid(eid):
    if isinstance(eid, str):
        if eid in _ALIASES:
            return _ALIASES[eid]
        try:
            return int(eid)
        except ValueError:
            raise ValueError(f"Unknown auditd record type alias: {eid!r}")
    return eid


def _pid():
    return str(random.randint(1000, 65535))

def _inode():
    return str(random.randint(100000, 999999))

def _ses():
    return str(random.randint(1, 100))

def _auid(user):
    return str(user.rid if user else 1000)

def _uid(user):
    return str(user.rid if user else 0)


def eid_1300(fields, host, user, **_):
    exe = fields.get("exe", "/usr/bin/bash")
    comm = exe.rsplit("/", 1)[-1] if "/" in exe else exe
    return {
        "arch": fields.get("arch", "c000003e"),
        "syscall": str(fields.get("syscall", "59")),
        "success": fields.get("success", "yes"),
        "exit": str(fields.get("exit", "0")),
        "ppid": fields.get("ppid", _pid()),
        "pid": fields.get("pid", _pid()),
        "auid": fields.get("auid", _auid(user)),
        "uid": fields.get("uid", _uid(user)),
        "gid": fields.get("gid", _uid(user)),
        "euid": fields.get("euid", _uid(user)),
        "suid": fields.get("suid", _uid(user)),
        "fsuid": fields.get("fsuid", _uid(user)),
        "egid": fields.get("egid", _uid(user)),
        "sgid": fields.get("sgid", _uid(user)),
        "fsgid": fields.get("fsgid", _uid(user)),
        "tty": fields.get("tty", "pts0"),
        "ses": fields.get("ses", _ses()),
        "comm": fields.get("comm", f'"{comm}"'),
        "exe": exe,
        "key": fields.get("key", '"exec_monitor"'),
    }


def eid_1309(fields, host, user, **_):
    args = fields.get("args", ["bash"])
    if isinstance(args, str):
        args = [args]
    result = {"argc": str(len(args))}
    for i, arg in enumerate(args):
        result[f"a{i}"] = str(arg)
    return result


def eid_1302(fields, host, user, **_):
    return {
        "item": str(fields.get("item", "0")),
        "name": fields.get("name", "/usr/bin/bash"),
        "inode": fields.get("inode", _inode()),
        "dev": fields.get("dev", "08:01"),
        "mode": fields.get("mode", "0100755"),
        "ouid": fields.get("ouid", "0"),
        "ogid": fields.get("ogid", "0"),
        "rdev": fields.get("rdev", "00:00"),
        "nametype": fields.get("nametype", "NORMAL"),
    }


def eid_1306(fields, host, user, **_):
    return {
        "saddr": fields.get("saddr", "02000050AC100A32"),
        "family": fields.get("family", "inet"),
        "laddr": fields.get("laddr", host.ip),
        "lport": str(fields.get("lport", str(random.randint(1024, 65535)))),
        "addr": fields.get("addr", "10.10.10.10"),
        "port": str(fields.get("port", "443")),
    }


def eid_1100(fields, host, user, **_):
    acct = fields.get("acct", user.username if user else "root")
    exe = fields.get("exe", "/usr/bin/sudo")
    hostname = fields.get("hostname", "?")
    addr = fields.get("addr", "?")
    terminal = fields.get("terminal", "/dev/pts/0")
    res = fields.get("res", "success")
    return {
        "pid": fields.get("pid", _pid()),
        "uid": fields.get("uid", _uid(user)),
        "auid": fields.get("auid", _auid(user)),
        "ses": fields.get("ses", _ses()),
        "msg": f'op=PAM:authentication acct="{acct}" exe="{exe}" hostname={hostname} addr={addr} terminal={terminal} res={res}',
    }


def eid_1101(fields, host, user, **_):
    uid_val = _uid(user)
    exe = fields.get("exe", "/usr/sbin/sshd")
    hostname = fields.get("hostname", "10.10.10.10")
    addr = fields.get("addr", hostname)
    terminal = fields.get("terminal", "ssh")
    res = fields.get("res", "success")
    return {
        "pid": fields.get("pid", _pid()),
        "uid": fields.get("uid", uid_val),
        "auid": fields.get("auid", _auid(user)),
        "ses": fields.get("ses", _ses()),
        "msg": f'op=login id={uid_val} exe="{exe}" hostname={hostname} addr={addr} terminal={terminal} res={res}',
    }


def eid_1103(fields, host, user, **_):
    acct = fields.get("acct", user.username if user else "root")
    exe = fields.get("exe", "/usr/bin/sudo")
    hostname = fields.get("hostname", "?")
    addr = fields.get("addr", "?")
    terminal = fields.get("terminal", "/dev/pts/0")
    res = fields.get("res", "success")
    return {
        "pid": fields.get("pid", _pid()),
        "uid": fields.get("uid", _uid(user)),
        "auid": fields.get("auid", _auid(user)),
        "ses": fields.get("ses", _ses()),
        "msg": f'op=PAM:setcred acct="{acct}" exe="{exe}" hostname={hostname} addr={addr} terminal={terminal} res={res}',
    }


_GENERATORS = {
    1300: eid_1300, 1309: eid_1309, 1302: eid_1302, 1306: eid_1306,
    1100: eid_1100, 1101: eid_1101, 1103: eid_1103,
}


def generate(eid, fields, host, user, spec, timestamp, ctx=None,
             session_label="default", process_label="default"):
    fn = _GENERATORS.get(eid)
    if fn is None:
        raise ValueError(f"Auditd EID {eid} not implemented.")
    return fn(fields=fields, host=host, user=user, spec=spec, timestamp=timestamp)
