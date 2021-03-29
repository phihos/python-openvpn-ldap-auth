import io
import os
import shutil
import stat
from typing import Iterable

import ldap
import pexpect
import pytest
import yaml
from ldap.ldapobject import SimpleLDAPObject

# INPUT PARAMS
LDAP_URL = os.environ['TEST_LDAP_URL']
LDAP_BASE_DN = os.environ['TEST_LDAP_BASE_DN']
LDAP_ADMIN_DN = os.environ['TEST_LDAP_ADMIN_DN']
LDAP_ADMIN_PASSWORD = os.environ['TEST_LDAP_ADMIN_PASSWORD']
LDAP_BIND_TIMEOUT = os.environ.get('TEST_LDAP_BIND_TIMEOUT', 5)
OPENVPN_SERVER_START_TIMEOUT = os.environ.get('TEST_OPENVPN_SERVER_START_TIMEOUT', 5)
OPENVPN_CLIENT_CONNECT_TIMEOUT = os.environ.get('TEST_OPENVPN_CLIENT_CONNECT_TIMEOUT', 2)
TEST_TIMEOUT = os.environ.get('TEST_TIMEOUT', 10)
TEST_PROMPT_DEFAULT_TIMEOUT = os.environ.get('TEST_PROMPT_DEFAULT_TIMEOUT', 3)
OPENVPN_BINARY = os.environ.get('TEST_OPENVPN_BINARY', shutil.which('openvpn'))

# PATHS
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
AUTH_SCRIPT_PATH = shutil.which('openvpn-ldap-auth')

# CONSTANTS: SERVER SETUP
OPENVPN_SERVER_PORT = 1194
OPENVPN_SERVER_DH_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'dh2048.pem'))
OPENVPN_SERVER_CA_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'ca.crt'))
OPENVPN_SERVER_CERT_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'server.crt'))
OPENVPN_SERVER_KEY_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'server.key'))
OPENVPN_SERVER_CHALLENGE_RESPONSE_PROMPT = 'Enter challenge response'
OPENVPN_SERVER_LDAP_CONFIG_PATH = '/etc/openvpn/ldap.yaml'

# CONSTANTS: CMD ARGS
OPENVPN_SERVER_ARGS = ['--mode', 'server', '--dev', 'tun', '--port', str(OPENVPN_SERVER_PORT), '--verb', '4',
                       '--verify-client-cert', 'none', '--tls-server', '--dh',
                       OPENVPN_SERVER_DH_FILE, '--ca', OPENVPN_SERVER_CA_FILE, '--cert',
                       OPENVPN_SERVER_CERT_FILE, '--key', OPENVPN_SERVER_KEY_FILE, '--script-security', '3', '--user',
                       'root', '--group', 'root', '--persist-key', '--persist-tun']
OPENVPN_SERVER_ARGS_VIA_FILE = OPENVPN_SERVER_ARGS + ['--auth-user-pass-verify', AUTH_SCRIPT_PATH,
                                                      'via-file']
OPENVPN_SERVER_ARGS_VIA_ENV = OPENVPN_SERVER_ARGS + ['--auth-user-pass-verify', AUTH_SCRIPT_PATH,
                                                     'via-env']
OPENVPN_CLIENT_ARGS = ('--client', '--dev', 'tun', '--proto', 'udp', '--remote', '127.0.0.1', str(OPENVPN_SERVER_PORT),
                       '--nobind', '--ca', OPENVPN_SERVER_CA_FILE, '--auth-user-pass')
OPENVPN_CLIENT_ARGS_WITH_CHALLENGE = OPENVPN_CLIENT_ARGS + ('--static-challenge',
                                                            OPENVPN_SERVER_CHALLENGE_RESPONSE_PROMPT, '1')
OPENVPN_CLIENT_ARGS_WITHOUT_CHALLENGE = OPENVPN_CLIENT_ARGS

# CONSTANTS: ldap.yaml CONFIGS
CONFIG_BASE = {
    'ldap': {
        'url': LDAP_URL,
        'bind_dn': LDAP_ADMIN_DN,
        'password': LDAP_ADMIN_PASSWORD,
    },
    'authorization': {
        'base_dn': LDAP_BASE_DN,
        'search_filter': '(uid={})'
    }
}
CONFIG_CHALLENGE_RESPONSE_APPEND = {**CONFIG_BASE, **{
    'authorization': {
        'base_dn': LDAP_BASE_DN,
        'static_challenge': 'append',
    }
}}
CONFIG_CHALLENGE_RESPONSE_PREPEND = {**CONFIG_BASE, **{
    'authorization': {
        'base_dn': LDAP_BASE_DN,
        'static_challenge': 'prepend',
    }
}}
CONFIG_CHALLENGE_RESPONSE_IGNORE = {**CONFIG_BASE, **{
    'authorization': {
        'base_dn': LDAP_BASE_DN,
        'static_challenge': 'ignore',
    }
}}

# CONSTANTS: TEST CREDENTIALS
TEST_USERNAME = 'testuser'
TEST_USER_DN = f"uid={TEST_USERNAME},{LDAP_BASE_DN}"
TEST_USER_PASSWORD = 'testpass'
TEST_USER_WRONG_PASSWORD = 'wrong_password'

# CONSTANTS: EXPECTED OPENVPN LOG FRAGMENTS
OPENVPN_LOG_INIT_COMPLETE = 'Initialization Sequence Completed'
OPENVPN_LOG_AUTH_SUCCEEDED_SERVER = 'authentication succeeded for username'
OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT = 'Initialization Sequence Completed'
OPENVPN_LOG_AUTH_FAILED_SERVER = 'verification failed for peer'
OPENVPN_LOG_AUTH_FAILED_CLIENT = 'AUTH_FAILED'


class Process:
    def __init__(self, cmd: str, args: Iterable, timeout=TEST_TIMEOUT):
        self._process = pexpect.spawn(cmd, args=list(args), logfile=io.BytesIO(), timeout=timeout)

    def check_in_output(self, expected_output: str, timeout=TEST_PROMPT_DEFAULT_TIMEOUT):
        try:
            self._process.expect(expected_output, timeout=timeout)
        except pexpect.EOF:
            pytest.fail(f"Process exited:\n\n{self._process.logfile.getvalue().decode()}\n")
        except pexpect.TIMEOUT:
            pytest.fail(f"Process timed out:\n\n{self._process.logfile.getvalue().decode()}\n")

    def check_not_in_output(self, unexpected_output: str, timeout=TEST_PROMPT_DEFAULT_TIMEOUT):
        try:
            self._process.expect(unexpected_output, timeout=timeout)
            pytest.fail(f"Unexpected output:\n\n{self._process.logfile.getvalue().decode()}\n")
        except (pexpect.EOF, pexpect.TIMEOUT):
            pass

    def send_input(self, input_line: str):
        self._process.sendline(input_line)

    def terminate(self):
        self._process.terminate()


class OpenVPNProcess(Process):

    def __init__(self, args: Iterable, timeout=TEST_TIMEOUT):
        super().__init__(OPENVPN_BINARY, args, timeout)

    def enter_username_password(self, username: str, password: str):
        self.check_in_output('Enter Auth Username:')
        self.send_input(username)
        self.check_in_output('Enter Auth Password:')
        self.send_input(password)

    def enter_challenge_response(self, response: str):
        self.check_in_output(OPENVPN_SERVER_CHALLENGE_RESPONSE_PROMPT)
        self.send_input(response)


@pytest.fixture
def connection() -> SimpleLDAPObject:
    con = ldap.initialize(LDAP_URL)
    con.set_option(ldap.OPT_NETWORK_TIMEOUT, LDAP_BIND_TIMEOUT)
    con.simple_bind_s(LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD)
    return con


def create_user(con: SimpleLDAPObject, dn: str, password: str):
    username = (dn.split(',')[0]).split('=')[1]
    ldap_obj = ((
        ('objectClass', [b'account', b'simpleSecurityObject']),
        ('uid', username.encode()),
        ('userPassword', password.encode()),
    ))
    try:
        con.add_s(dn, ldap_obj)
    except ldap.ALREADY_EXISTS:
        pass


def run_openvpn_server_with_args(args: list) -> Process:
    os.makedirs('/dev/net', exist_ok=True)
    try:
        os.mknod('/dev/net/tun', mode=0o666 | stat.S_IFCHR, device=os.makedev(10, 200))
    except FileExistsError:
        pass
    process = OpenVPNProcess(args)
    process.check_in_output(OPENVPN_LOG_INIT_COMPLETE, timeout=OPENVPN_SERVER_START_TIMEOUT)
    return process


@pytest.fixture(autouse=True)
def create_test_user(connection: SimpleLDAPObject):
    create_user(connection, TEST_USER_DN, TEST_USER_PASSWORD)


@pytest.fixture
def openvpn_server(request) -> Process:
    process = run_openvpn_server_with_args(request.param)
    yield process
    process.terminate()


@pytest.fixture
def config(request) -> Process:
    with open(OPENVPN_SERVER_LDAP_CONFIG_PATH, 'w') as f:
        f.write(yaml.dump(request.param))
    yield request.param
    os.remove(OPENVPN_SERVER_LDAP_CONFIG_PATH)


@pytest.mark.timeout(TEST_TIMEOUT)
@pytest.mark.parametrize("openvpn_server", [OPENVPN_SERVER_ARGS_VIA_ENV, OPENVPN_SERVER_ARGS_VIA_FILE], indirect=True)
@pytest.mark.parametrize("config", [CONFIG_CHALLENGE_RESPONSE_IGNORE, CONFIG_CHALLENGE_RESPONSE_PREPEND,
                                    CONFIG_CHALLENGE_RESPONSE_APPEND], indirect=True)
def test_authentication_with_challenge_response_should_succeed(connection: SimpleLDAPObject, openvpn_server: Process,
                                                               config: dict):
    """Splitting the user password between user pass and challenge response should pass authentication."""
    process = OpenVPNProcess(OPENVPN_CLIENT_ARGS_WITH_CHALLENGE)
    static_challenge_mode = config['authorization']['static_challenge']
    if static_challenge_mode == 'ignore':
        password = TEST_USER_PASSWORD
        challenge_response = ''
    elif static_challenge_mode == 'prepend':
        password = TEST_USER_PASSWORD[1:]
        challenge_response = TEST_USER_PASSWORD[:1]
    else:
        password = TEST_USER_PASSWORD[:1]
        challenge_response = TEST_USER_PASSWORD[1:]
    process.enter_username_password(TEST_USERNAME, password)
    process.enter_challenge_response(challenge_response)
    openvpn_server.check_in_output(OPENVPN_LOG_AUTH_SUCCEEDED_SERVER)
    process.check_in_output(OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT)


@pytest.mark.timeout(TEST_TIMEOUT)
@pytest.mark.parametrize("openvpn_server", [OPENVPN_SERVER_ARGS_VIA_ENV, OPENVPN_SERVER_ARGS_VIA_FILE], indirect=True)
@pytest.mark.parametrize("config", [CONFIG_CHALLENGE_RESPONSE_IGNORE, CONFIG_CHALLENGE_RESPONSE_PREPEND,
                                    CONFIG_CHALLENGE_RESPONSE_APPEND], indirect=True)
def test_authentication_without_challenge_response_should_succeed(connection: SimpleLDAPObject, openvpn_server: Process,
                                                                  config: dict):
    process = OpenVPNProcess(OPENVPN_CLIENT_ARGS_WITHOUT_CHALLENGE)
    process.enter_username_password(TEST_USERNAME, TEST_USER_PASSWORD)
    openvpn_server.check_in_output(OPENVPN_LOG_AUTH_SUCCEEDED_SERVER)
    process.check_in_output(OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT)


@pytest.mark.timeout(TEST_TIMEOUT)
@pytest.mark.parametrize("openvpn_server", [OPENVPN_SERVER_ARGS_VIA_ENV, OPENVPN_SERVER_ARGS_VIA_FILE], indirect=True)
@pytest.mark.parametrize("config", [CONFIG_CHALLENGE_RESPONSE_IGNORE, CONFIG_CHALLENGE_RESPONSE_PREPEND,
                                    CONFIG_CHALLENGE_RESPONSE_APPEND], indirect=True)
def test_authentication_with_challenge_response_with_wrong_password_should_fail(connection: SimpleLDAPObject,
                                                                                openvpn_server: Process,
                                                                                config: dict):
    process = OpenVPNProcess(OPENVPN_CLIENT_ARGS_WITH_CHALLENGE)
    process.enter_username_password(TEST_USERNAME, TEST_USER_WRONG_PASSWORD)
    process.enter_challenge_response(TEST_USER_WRONG_PASSWORD)
    process.check_in_output(OPENVPN_LOG_AUTH_FAILED_CLIENT)
    process.check_not_in_output(OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT)
    openvpn_server.check_in_output(OPENVPN_LOG_AUTH_FAILED_SERVER)


@pytest.mark.timeout(TEST_TIMEOUT)
@pytest.mark.parametrize("openvpn_server", [OPENVPN_SERVER_ARGS_VIA_ENV, OPENVPN_SERVER_ARGS_VIA_FILE], indirect=True)
@pytest.mark.parametrize("config", [CONFIG_CHALLENGE_RESPONSE_IGNORE, CONFIG_CHALLENGE_RESPONSE_PREPEND,
                                    CONFIG_CHALLENGE_RESPONSE_APPEND], indirect=True)
def test_authentication_without_challenge_response_with_wrong_password_should_fail(connection: SimpleLDAPObject,
                                                                                   openvpn_server: Process,
                                                                                   config: dict):
    process = OpenVPNProcess(OPENVPN_CLIENT_ARGS_WITHOUT_CHALLENGE)
    process.enter_username_password(TEST_USERNAME, TEST_USER_WRONG_PASSWORD)
    process.check_in_output(OPENVPN_LOG_AUTH_FAILED_CLIENT)
    process.check_not_in_output(OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT)
    openvpn_server.check_in_output(OPENVPN_LOG_AUTH_FAILED_SERVER)
