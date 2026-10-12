"""OpenVPN ``auth-user-pass-verify`` script that authenticates users via an LDAP simple bind."""

import logging
import os
import sys
from base64 import b64decode
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import ldap
import yaml
from ldap.filter import escape_filter_chars

LDAP_CONFIG = Path("/etc/openvpn/ldap.yaml")
USERNAME_PLACEHOLDER = "{}"

log = logging.getLogger("openvpn-ldap-auth")


class StaticChallenge(StrEnum):
    IGNORE = "ignore"
    PREPEND = "prepend"
    APPEND = "append"


class InvalidConfigException(Exception):
    """Raise when the config validation failed."""


class InvalidInputException(Exception):
    """Raise when OpenVPN handed us credentials we cannot parse."""


class LDAPException(Exception):
    """Raise when issues occur while interacting with the LDAP server."""


_REQUIRED = object()
# section -> key -> (type, default)
_SCHEMA: dict[str, dict[str, tuple[type, Any]]] = {
    "ldap": {
        "url": (str, _REQUIRED),
        "bind_dn": (str, _REQUIRED),
        "password": (str, _REQUIRED),
        "timeout": (int, 5),
    },
    "authorization": {
        "base_dn": (str, _REQUIRED),
        "search_filter": (str, "(uid={})"),
        "static_challenge": (str, StaticChallenge.IGNORE.value),
    },
}


@dataclass(frozen=True)
class Config:
    """User-defined configuration from ``/etc/openvpn/ldap.yaml``."""

    url: str
    bind_dn: str
    password: str = field(repr=False)
    timeout: int
    base_dn: str
    search_filter: str
    static_challenge: StaticChallenge

    @classmethod
    def from_dict(cls, raw: object) -> "Config":
        errors: list[str] = []
        values: dict[str, Any] = {}
        if not isinstance(raw, dict):
            raise InvalidConfigException("Invalid config: top level must be a mapping")
        errors += [f"{key}: unknown section" for key in raw.keys() - _SCHEMA.keys()]
        for section_name, schema in _SCHEMA.items():
            section = raw.get(section_name)
            if not isinstance(section, dict):
                errors.append(f"{section_name}: required mapping")
                continue
            errors += [
                f"{section_name}.{key}: unknown field" for key in section.keys() - schema.keys()
            ]
            for key, (kind, default) in schema.items():
                value = section.get(key, default)
                if value is _REQUIRED:
                    errors.append(f"{section_name}.{key}: required field")
                elif type(value) is not kind:  # exact match: YAML `true` must not pass as int
                    errors.append(f"{section_name}.{key}: must be of type {kind.__name__}")
                else:
                    values[key] = value
        if errors:
            raise InvalidConfigException(f"Invalid config: {'; '.join(sorted(errors))}")

        try:
            values["static_challenge"] = StaticChallenge(values["static_challenge"])
        except ValueError:
            allowed = ", ".join(StaticChallenge)
            raise InvalidConfigException(
                f"Invalid config: authorization.static_challenge must be one of {allowed}"
            ) from None
        if USERNAME_PLACEHOLDER not in values["search_filter"]:
            # without the placeholder every login would bind against the same DN
            raise InvalidConfigException(
                f"Invalid config: authorization.search_filter must contain {USERNAME_PLACEHOLDER}"
            )
        return cls(**values)

    @classmethod
    def from_file(cls, path: Path) -> "Config":
        try:
            with path.open(encoding="utf-8") as stream:
                return cls.from_dict(yaml.safe_load(stream))
        except (OSError, yaml.YAMLError) as e:
            raise InvalidConfigException(f"Cannot read config {path}: {e}") from e


@dataclass(frozen=True)
class Credentials:
    """Username and password as handed over by OpenVPN."""

    username: str
    password: str = field(repr=False)
    challenge_response: str = field(default="", repr=False)

    @classmethod
    def from_openvpn(cls, argv: Sequence[str], environ: Mapping[str, str]) -> "Credentials":
        """Read credentials passed `via-env` or `via-file`."""
        if "password" in environ:
            username, password = environ.get("username", ""), environ["password"]
        else:
            if len(argv) < 2:
                raise InvalidInputException("Expected credentials file as first argument")
            # splitlines() instead of strip(): leading/trailing spaces belong to the password
            lines = Path(argv[1]).read_text(encoding="utf-8").splitlines()
            if len(lines) < 2:
                raise InvalidInputException("Credentials file must contain username and password")
            username, password = lines[0], lines[1]
        return cls._decode_static_challenge(username, password)

    @classmethod
    def _decode_static_challenge(cls, username: str, password: str) -> "Credentials":
        if not password.startswith("SCRV1:"):
            log.debug("Using password verbatim")
            return cls(username, password)
        log.debug("Extracting static-challenge password and OTP")
        try:
            _, b64_password, b64_response = password.split(":")
            return cls(
                username,
                b64decode(b64_password, validate=True).decode(),
                b64decode(b64_response, validate=True).decode(),
            )
        except ValueError as e:  # wrong part count, bad base64 or bad UTF-8
            raise InvalidInputException("Malformed static-challenge (SCRV1) password") from e

    def bind_password(self, mode: StaticChallenge) -> str:
        """Combine password and challenge response according to ``mode``."""
        if not self.challenge_response or mode is StaticChallenge.IGNORE:
            return self.password
        if mode is StaticChallenge.PREPEND:
            return self.challenge_response + self.password
        return self.password + self.challenge_response


def _bind(config: Config, dn: str, password: str) -> Any:
    con = ldap.initialize(config.url)
    con.set_option(ldap.OPT_NETWORK_TIMEOUT, config.timeout)
    con.set_option(ldap.OPT_TIMEOUT, config.timeout)
    try:
        con.simple_bind_s(dn, password)
    except ldap.INVALID_CREDENTIALS as e:
        raise LDAPException(f"Invalid password for {dn}") from e
    except ldap.LDAPError as e:
        raise LDAPException(f"Simple bind failed for {dn}: {e}") from e
    return con


def _find_user_dn(config: Config, username: str) -> str:
    search_filter = config.search_filter.replace(
        USERNAME_PLACEHOLDER, escape_filter_chars(username)
    )
    con = _bind(config, config.bind_dn, config.password)
    try:
        # "1.1" = return no attributes, we only need the DN
        results = con.search_st(
            config.base_dn, ldap.SCOPE_SUBTREE, search_filter, ["1.1"], timeout=config.timeout
        )
    except ldap.LDAPError as e:
        raise LDAPException(f"Search for {username} failed: {e}") from e
    finally:
        con.unbind_s()

    dns = [dn for dn, _ in results if dn]  # referrals come back with dn=None
    if len(dns) > 1:
        raise LDAPException(
            f"User {username} found multiple times: Please check authorization.search_filter"
        )
    if not dns:
        raise LDAPException(f"User {username} not found")
    return str(dns[0])


def authenticate(config: Config, username: str, password: str) -> None:
    """Raise :class:`LDAPException` unless ``username`` can bind with ``password``."""
    if not password:
        # an empty password turns the bind into an RFC 4513 unauthenticated bind,
        # which some servers answer with success
        raise LDAPException(f"Empty password for {username} rejected")
    user_dn = _find_user_dn(config, username)
    _bind(config, user_dn, password).unbind_s()


def setup_logging(verbosity: int) -> None:
    if verbosity >= 4:
        level = logging.DEBUG
    elif verbosity == 3:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=level)


def main() -> None:
    setup_logging(int(os.environ.get("verb", "1")))  # noqa: SIM112 - name set by OpenVPN
    try:
        config = Config.from_file(LDAP_CONFIG)
        credentials = Credentials.from_openvpn(sys.argv, os.environ)
        log.info("Authenticating %s", credentials.username)
        authenticate(
            config, credentials.username, credentials.bind_password(config.static_challenge)
        )
    except (InvalidConfigException, InvalidInputException, LDAPException) as e:
        log.error("Authentication failed: %s", e)
        sys.exit(1)
    except Exception:
        log.exception("Unexpected error while authenticating")
        sys.exit(1)
    log.info("Authenticated %s", credentials.username)


if __name__ == "__main__":
    main()
