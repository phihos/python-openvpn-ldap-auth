import logging
from base64 import b64encode
from pathlib import Path
from typing import Any

import ldap
import pytest

from openvpn_ldap_auth import main as auth
from openvpn_ldap_auth.main import (
    Config,
    Credentials,
    InvalidConfigException,
    InvalidInputException,
    LDAPException,
    StaticChallenge,
)

RAW_CONFIG: dict[str, Any] = {
    "ldap": {"url": "ldap://ldap", "bind_dn": "cn=admin", "password": "secret"},
    "authorization": {"base_dn": "dc=example"},
}


def config(**authorization: Any) -> Config:
    return Config.from_dict(
        {**RAW_CONFIG, "authorization": {**RAW_CONFIG["authorization"], **authorization}}
    )


def scrv1(password: str, response: str) -> str:
    return f"SCRV1:{b64encode(password.encode()).decode()}:{b64encode(response.encode()).decode()}"


# --- Config -----------------------------------------------------------------


def test_config_defaults() -> None:
    cfg = config()
    assert cfg.timeout == 5
    assert cfg.search_filter == "(uid={})"
    assert cfg.static_challenge is StaticChallenge.IGNORE


def test_config_password_not_in_repr() -> None:
    assert "secret" not in repr(config())


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (None, "top level must be a mapping"),
        ({"authorization": RAW_CONFIG["authorization"]}, "ldap: required mapping"),
        ({**RAW_CONFIG, "extra": {}}, "extra: unknown section"),
        ({**RAW_CONFIG, "ldap": {"url": "ldap://x"}}, "ldap.bind_dn: required field"),
        ({**RAW_CONFIG, "ldap": {**RAW_CONFIG["ldap"], "timeout": "5"}}, "must be of type int"),
        ({**RAW_CONFIG, "ldap": {**RAW_CONFIG["ldap"], "timeout": True}}, "must be of type int"),
        ({**RAW_CONFIG, "ldap": {**RAW_CONFIG["ldap"], "pasword": "x"}}, "ldap.pasword: unknown"),
    ],
)
def test_config_invalid(raw: Any, message: str) -> None:
    with pytest.raises(InvalidConfigException, match=message):
        Config.from_dict(raw)


def test_config_invalid_static_challenge() -> None:
    with pytest.raises(InvalidConfigException, match="ignore, prepend, append"):
        config(static_challenge="sideways")


def test_config_search_filter_needs_placeholder() -> None:
    with pytest.raises(InvalidConfigException, match="must contain"):
        config(search_filter="(uid=admin)")


def test_config_from_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigException, match="Cannot read config"):
        Config.from_file(tmp_path / "nope.yaml")


def test_config_from_file(tmp_path: Path) -> None:
    path = tmp_path / "ldap.yaml"
    path.write_text(
        "ldap: {url: 'ldap://x', bind_dn: 'cn=a', password: 'p', timeout: 3}\n"
        "authorization: {base_dn: 'dc=x', static_challenge: append}\n"
    )
    cfg = Config.from_file(path)
    assert (cfg.timeout, cfg.static_challenge) == (3, StaticChallenge.APPEND)


# --- Credentials ------------------------------------------------------------


def test_credentials_via_env() -> None:
    creds = Credentials.from_openvpn(["script"], {"username": "alice", "password": "pw"})
    assert (creds.username, creds.password) == ("alice", "pw")


def test_credentials_via_file_keeps_surrounding_spaces(tmp_path: Path) -> None:
    path = tmp_path / "creds"
    path.write_text("alice\n  pw  \n")
    creds = Credentials.from_openvpn(["script", str(path)], {})
    assert (creds.username, creds.password) == ("alice", "  pw  ")


def test_credentials_missing_file_argument() -> None:
    with pytest.raises(InvalidInputException):
        Credentials.from_openvpn(["script"], {})


def test_credentials_static_challenge_decoded() -> None:
    creds = Credentials.from_openvpn(["script"], {"username": "a", "password": scrv1("pw", "123")})
    assert (creds.password, creds.challenge_response) == ("pw", "123")


@pytest.mark.parametrize("password", ["SCRV1:only-one-part", "SCRV1:!!!:!!!", "SCRV1:a:b:c"])
def test_credentials_malformed_static_challenge(password: str) -> None:
    with pytest.raises(InvalidInputException):
        Credentials.from_openvpn(["script"], {"username": "a", "password": password})


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (StaticChallenge.IGNORE, "pw"),
        (StaticChallenge.PREPEND, "123pw"),
        (StaticChallenge.APPEND, "pw123"),
    ],
)
def test_bind_password(mode: StaticChallenge, expected: str) -> None:
    assert Credentials("a", "pw", "123").bind_password(mode) == expected


def test_bind_password_without_response_ignores_mode() -> None:
    assert Credentials("a", "pw").bind_password(StaticChallenge.APPEND) == "pw"


# --- authenticate -----------------------------------------------------------


class FakeLDAP:
    """Stands in for an LDAP connection. ``users`` maps DN -> password."""

    def __init__(self, users: dict[str, str], results: list[tuple[str | None, Any]]) -> None:
        self.users = users
        self.results = results
        self.filters: list[str] = []

    def set_option(self, *_: Any) -> None:
        pass

    def simple_bind_s(self, dn: str, password: str) -> None:
        if self.users.get(dn) != password:
            raise ldap.INVALID_CREDENTIALS()

    def search_st(self, base: str, scope: int, filterstr: str, *_: Any, **__: Any) -> Any:
        self.filters.append(filterstr)
        return self.results

    def unbind_s(self) -> None:
        pass


@pytest.fixture
def fake_ldap(monkeypatch: pytest.MonkeyPatch) -> FakeLDAP:
    fake = FakeLDAP({"cn=admin": "secret", "uid=alice": "pw"}, [("uid=alice", {})])
    monkeypatch.setattr(ldap, "initialize", lambda url: fake)
    return fake


def test_authenticate_success(fake_ldap: FakeLDAP) -> None:
    auth.authenticate(config(), "alice", "pw")
    assert fake_ldap.filters == ["(uid=alice)"]


def test_authenticate_wrong_password(fake_ldap: FakeLDAP) -> None:
    with pytest.raises(LDAPException, match="Invalid password for uid=alice"):
        auth.authenticate(config(), "alice", "wrong")


def test_authenticate_rejects_empty_password(fake_ldap: FakeLDAP) -> None:
    fake_ldap.users["uid=alice"] = ""  # a server accepting unauthenticated binds
    with pytest.raises(LDAPException, match="Empty password"):
        auth.authenticate(config(), "alice", "")


def test_authenticate_escapes_username(fake_ldap: FakeLDAP) -> None:
    auth.authenticate(config(), "alice)(uid=*", "pw")
    assert fake_ldap.filters == [r"(uid=alice\29\28uid=\2a)"]


def test_authenticate_ignores_referrals(fake_ldap: FakeLDAP) -> None:
    fake_ldap.results = [("uid=alice", {}), (None, ["ldap://elsewhere"])]
    auth.authenticate(config(), "alice", "pw")


@pytest.mark.parametrize(
    ("results", "message"),
    [([], "not found"), ([("uid=alice", {}), ("uid=alice2", {})], "found multiple times")],
)
def test_authenticate_lookup_failures(
    fake_ldap: FakeLDAP, results: list[tuple[str, Any]], message: str
) -> None:
    fake_ldap.results = results
    with pytest.raises(LDAPException, match=message):
        auth.authenticate(config(), "alice", "pw")


def test_authenticate_service_bind_failure(fake_ldap: FakeLDAP) -> None:
    fake_ldap.users["cn=admin"] = "rotated"
    with pytest.raises(LDAPException, match="Invalid password for cn=admin"):
        auth.authenticate(config(), "alice", "pw")


# --- main / logging ---------------------------------------------------------


@pytest.mark.parametrize(
    ("verb", "level"),
    [(1, logging.WARNING), (3, logging.INFO), (4, logging.DEBUG), (11, logging.DEBUG)],
)
def test_setup_logging(monkeypatch: pytest.MonkeyPatch, verb: int, level: int) -> None:
    calls: list[int] = []
    monkeypatch.setattr(logging, "basicConfig", lambda **kw: calls.append(kw["level"]))
    auth.setup_logging(verb)
    assert calls == [level]


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "ldap.yaml"
    path.write_text(
        "ldap: {url: 'ldap://x', bind_dn: 'cn=admin', password: 'secret'}\n"
        "authorization: {base_dn: 'dc=x'}\n"
    )
    monkeypatch.setattr(auth, "LDAP_CONFIG", path)


@pytest.mark.usefixtures("config_file")
@pytest.mark.parametrize(("password", "exit_code"), [("pw", None), ("wrong", 1)])
def test_main_exit_code(
    fake_ldap: FakeLDAP, monkeypatch: pytest.MonkeyPatch, password: str, exit_code: int | None
) -> None:
    monkeypatch.setattr("sys.argv", ["openvpn-ldap-auth"])
    monkeypatch.setenv("username", "alice")
    monkeypatch.setenv("password", password)
    if exit_code is None:
        auth.main()
    else:
        with pytest.raises(SystemExit) as exc:
            auth.main()
        assert exc.value.code == exit_code
