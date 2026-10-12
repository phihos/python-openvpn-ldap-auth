import contextlib
import io
import os
import stat
from collections.abc import Iterable

import ldap
import pexpect
import pytest
from ldap.ldapobject import SimpleLDAPObject

from tests.system.constants import (
    LDAP_ADMIN_DN,
    LDAP_ADMIN_PASSWORD,
    LDAP_BIND_TIMEOUT,
    LDAP_URL,
    OPENVPN_BINARY,
    OPENVPN_LOG_SERVER_INIT_COMPLETE,
    OPENVPN_SERVER_CHALLENGE_RESPONSE_PROMPT,
    OPENVPN_SERVER_START_TIMEOUT,
    TEST_PROMPT_DEFAULT_TIMEOUT,
    TEST_TIMEOUT,
)


class Process:
    def __init__(self, cmd: str, args: Iterable, timeout=TEST_TIMEOUT):
        self._process = pexpect.spawn(cmd, args=list(args), logfile=io.BytesIO(), timeout=timeout)

    def check_in_output(self, expected_output: str, timeout=TEST_PROMPT_DEFAULT_TIMEOUT):
        try:
            self._process.expect(expected_output, timeout=timeout)
        except pexpect.EOF:
            pytest.fail(f"Process exited:\n\n{self.output()}\n")
        except pexpect.TIMEOUT:
            pytest.fail(f"Process timed out:\n\n{self.output()}\n")

    def check_not_in_output(self, unexpected_output: str, timeout=TEST_PROMPT_DEFAULT_TIMEOUT):
        try:
            self._process.expect(unexpected_output, timeout=timeout)
            pytest.fail(f"Unexpected output:\n\n{self.output()}\n")
        except (pexpect.EOF, pexpect.TIMEOUT):
            pass

    def send_input(self, input_line: str):
        self._process.sendline(input_line)

    def terminate(self):
        terminated = self._process.terminate(force=True)
        if not terminated:
            pytest.fail(f"Process could not be terminated:\n\n{self.output()}\n")

    def output(self):
        return self._process.logfile.getvalue().decode()


class OpenVPNProcess(Process):
    def __init__(self, args: Iterable, timeout=TEST_TIMEOUT):
        super().__init__(OPENVPN_BINARY, args, timeout)

    def enter_username_password(self, username: str, password: str):
        self.check_in_output("Enter Auth Username:")
        self.send_input(username)
        self.check_in_output("Enter Auth Password:")
        self.send_input(password)

    def enter_challenge_response(self, response: str):
        self.check_in_output(OPENVPN_SERVER_CHALLENGE_RESPONSE_PROMPT)
        self.send_input(response)


def create_user(con: SimpleLDAPObject, dn: str, password: str):
    username = (dn.split(",")[0]).split("=")[1]
    ldap_obj = (
        ("objectClass", [b"account", b"simpleSecurityObject"]),
        ("uid", username.encode()),
        ("userPassword", password.encode()),
    )
    with contextlib.suppress(ldap.ALREADY_EXISTS):
        con.add_s(dn, ldap_obj)


def delete_user(con: SimpleLDAPObject, dn: str):
    con.delete_s(dn)


def run_openvpn_server_with_args(args: list) -> Process:
    os.makedirs("/dev/net", exist_ok=True)
    with contextlib.suppress(FileExistsError):
        os.mknod("/dev/net/tun", mode=0o666 | stat.S_IFCHR, device=os.makedev(10, 200))
    process = OpenVPNProcess(args)
    process.check_in_output(OPENVPN_LOG_SERVER_INIT_COMPLETE, timeout=OPENVPN_SERVER_START_TIMEOUT)
    return process


def init_ldap_connection():
    con = ldap.initialize(LDAP_URL)
    con.set_option(ldap.OPT_NETWORK_TIMEOUT, LDAP_BIND_TIMEOUT)
    con.simple_bind_s(LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)
    return con
