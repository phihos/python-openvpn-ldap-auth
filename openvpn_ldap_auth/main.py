#!/usr/bin/python3
import logging
import os
import sys
import traceback
from base64 import b64decode

import ldap
import yaml
from cerberus import Validator
from ldap.ldapobject import SimpleLDAPObject

LDAP_CONFIG = '/etc/openvpn/ldap.yaml'

STATIC_CHALLENGE_IGNORE = 'ignore'
STATIC_CHALLENGE_PREPEND = 'prepend'
STATIC_CHALLENGE_APPEND = 'append'
STATIC_CHALLENGE_OPTS = (
    STATIC_CHALLENGE_IGNORE,
    STATIC_CHALLENGE_PREPEND,
    STATIC_CHALLENGE_APPEND
)


def setup_logging(verbosity: int):
    if verbosity == 4:
        level = logging.DEBUG
    elif verbosity == 3:
        level = logging.INFO
    else:
        level = logging.WARN
    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=level)


class InvalidConfigException(Exception):
    """Raise when the config validation failed."""


class LDAPException(Exception):
    """Raise when issues occur while interacting with the LDAP server."""


class Config:
    """Encapsulate user-defined configuration."""

    LDAP_CONFIG_SCHEMA = {
        'ldap': {
            'required': True,
            'type': 'dict',
            'schema': {
                'url': {
                    'required': True,
                    'type': 'string',
                },
                'bind_dn': {
                    'required': True,
                    'type': 'string',
                },
                'password': {
                    'required': True,
                    'type': 'string',
                },
                'timeout': {
                    'type': 'integer',
                    'default': 5,
                },
            },
        },
        'authorization': {
            'required': True,
            'type': 'dict',
            'schema': {
                'base_dn': {
                    'required': True,
                    'type': 'string',
                },
                'search_filter': {
                    'type': 'string',
                    'default': '(uid={})',
                },
                'static_challenge': {
                    'type': 'string',
                    'allowed': STATIC_CHALLENGE_OPTS,
                    'default': 'ignore',
                }
            }
        }
    }

    def __init__(self, config: dict):
        validator = Validator()
        is_valid = validator.validate(config, self.LDAP_CONFIG_SCHEMA)
        if not is_valid:
            raise InvalidConfigException(f"Invalid config: {validator.errors}")
        self._config = validator.document  # use normalized copy

    @property
    def url(self) -> str:
        return self._config['ldap']['url']

    @property
    def bind_dn(self) -> str:
        return self._config['ldap']['bind_dn']

    @property
    def password(self) -> str:
        return self._config['ldap']['password']

    @property
    def timeout(self) -> int:
        return self._config['ldap']['timeout']

    @property
    def base_dn(self) -> str:
        return self._config['authorization']['base_dn']

    @property
    def search_filter(self) -> str:
        return self._config['authorization']['search_filter']

    @property
    def static_challenge_mode(self) -> str:
        return self._config['authorization']['static_challenge']

    @staticmethod
    def from_file(path: str):
        with open(path, 'r', encoding='utf-8') as stream:
            config = yaml.safe_load(stream)
        return Config(config=config)


class OpenVPNParameters:

    def __init__(self, static_challenge_mode: str):
        self.static_challenge_mode = static_challenge_mode
        self.user = None
        self._raw_password = None
        self._password = None
        self._challenge_response = None
        self.verbosity = None
        self.config_file = None
        if os.environ.get('password', False):
            self._extract_credentials_from_environment()
        else:
            self._extract_credentials_from_input_file()
        self._decode_password()
        self._extract_other_parameters_from_evironment()

    def _extract_credentials_from_environment(self):
        self.user = os.environ['username']
        self._raw_password = os.environ['password']

    def _extract_credentials_from_input_file(self):
        tmp_file = open(sys.argv[1], 'r', encoding='utf-8')
        lines = tmp_file.readlines()
        self.user = lines[0].strip()
        self._raw_password = lines[1].strip()

    def _decode_password(self):
        if self._raw_password.startswith('SCRV1'):
            logging.debug('Extracting static-challenge password and OTP')
            password_parts = self._raw_password.split(':')
            self._password = b64decode(password_parts[1])
            self._challenge_response = b64decode(password_parts[2])
        else:
            logging.debug('Using password verbatim')
            self._password = self._raw_password

    def _extract_other_parameters_from_evironment(self):
        self.verbosity = int(os.environ.get('verb', 1))
        self.config_file = os.environ['config'] if 'config' in os.environ else None

    @property
    def full_password(self):
        """Concatenate the actual password with the challenge response if applicable."""
        if self._challenge_response:
            if self.static_challenge_mode == STATIC_CHALLENGE_IGNORE:
                logging.debug('Ignoring challenge reponse')
                return self._password
            elif self.static_challenge_mode == STATIC_CHALLENGE_PREPEND:
                logging.debug('Prepending challenge reponse')
                return self._challenge_response + self._password
            else:
                logging.debug('Appending challenge reponse')
                return self._password + self._challenge_response
        else:
            return self._password


class LDAPAuthenticator:

    def __init__(self, ldap_url: str, bind_dn: str, bind_password: str, user_search_base: str,
                 user_search_template: str, timeout: int):
        self._ldap_url = ldap_url
        self._user_search_base = user_search_base
        self._user_search_template = user_search_template
        self._timeout = timeout
        self._connection = self._establish_ldap_connection(bind_dn, bind_password)

    def _establish_ldap_connection(self, bind_dn: str, password: str) -> SimpleLDAPObject:
        con = ldap.initialize(self._ldap_url)
        con.set_option(ldap.OPT_NETWORK_TIMEOUT, self._timeout)
        try:
            con.simple_bind_s(bind_dn, password)
        except ldap.INVALID_CREDENTIALS:
            raise LDAPException(f"Invalid password for {bind_dn}")
        except ldap.LDAPError as e:
            raise LDAPException(f"Simple bind failed for {bind_dn}: {e}")
        return con

    def _find_user(self, username):
        results = self._connection.search_s(base=self._user_search_base, scope=ldap.SCOPE_SUBTREE,
                                            filterstr=self._user_search_template.format(username), attrlist=[])
        results = [result[0] for result in results]  # extract DNs only

        if len(results) > 1:
            raise LDAPException(f"User {username} found multiple times: Please check authorization.search_filter")
        elif len(results) == 0:
            raise LDAPException(f"User {username} not found")

        return results[0]

    def authenticate(self, username: str, password: str):
        user_dn = self._find_user(username)
        self._establish_ldap_connection(user_dn, password)


def main():
    try:
        config = Config.from_file(LDAP_CONFIG)
        vpn_params = OpenVPNParameters(config.static_challenge_mode)
        setup_logging(vpn_params.verbosity)
        logging.info(f"Authenticating {vpn_params.user}")
        authenticator = LDAPAuthenticator(config.url, config.bind_dn, config.password, config.base_dn,
                                          config.search_filter, config.timeout)
        authenticator.authenticate(vpn_params.user, vpn_params.full_password)
    except Exception as e:
        logging.error(f"Exception while authenticating: {e}")
        traceback.print_exc()
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
