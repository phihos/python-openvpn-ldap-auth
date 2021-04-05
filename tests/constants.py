import os
import shutil
from datetime import datetime

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
PYTHON_VERSION = os.environ.get('python_version', 'please set "python_version" in the env vars')
OPENVPN_VERSION = os.environ.get('openvpn_version', 'please set "openvpn_version" in the env vars')

# PATHS
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
AUTH_SCRIPT_PATH = shutil.which('openvpn-ldap-auth')
AUTH_SCRIPT_PATH_PYINSTALLER = shutil.which('openvpn-ldap-auth-pyinstaller')
BENCHMARK_DIR = os.path.join(
    SCRIPT_DIR, os.pardir, 'benchmark',
    f"python{PYTHON_VERSION}-openvpn{OPENVPN_VERSION}-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}"
)

# CONSTANTS: SERVER SETUP
OPENVPN_SERVER_PORT = 1194
OPENVPN_SERVER_DH_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'dh2048.pem'))
OPENVPN_SERVER_CA_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'ca.crt'))
OPENVPN_SERVER_CERT_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'server.crt'))
OPENVPN_SERVER_KEY_FILE = os.path.realpath(os.path.join(SCRIPT_DIR, 'resources', 'server', 'server.key'))
OPENVPN_SERVER_CHALLENGE_RESPONSE_PROMPT = 'Enter challenge response'
OPENVPN_SERVER_LDAP_CONFIG_PATH = '/etc/openvpn/ldap.yaml'
OPENVPN_SERVER_LDAP_C_CONFIG_PATH = '/etc/openvpn/ldap.conf'

# CONSTANTS: CMD ARGS
OPENVPN_SERVER_ARGS = ['--mode', 'server', '--server', '10.5.99.0', '255.255.255.0', '--dev', 'tun', '--port',
                       str(OPENVPN_SERVER_PORT), '--verb', '4', '--keepalive', '10', '120',
                       '--verify-client-cert', 'none', '--tls-server', '--dh',
                       OPENVPN_SERVER_DH_FILE, '--ca', OPENVPN_SERVER_CA_FILE, '--cert',
                       OPENVPN_SERVER_CERT_FILE, '--key', OPENVPN_SERVER_KEY_FILE, '--script-security', '3', '--user',
                       'root', '--group', 'root', '--duplicate-cn', '--max-clients', '1000', '--status',
                       'openvpn-status.log', '--topology', 'subnet']
OPENVPN_SERVER_ARGS_VIA_FILE = OPENVPN_SERVER_ARGS + ['--auth-user-pass-verify', AUTH_SCRIPT_PATH,
                                                      'via-file']
OPENVPN_SERVER_ARGS_VIA_ENV = OPENVPN_SERVER_ARGS + ['--auth-user-pass-verify', AUTH_SCRIPT_PATH,
                                                     'via-env']
OPENVPN_SERVER_ARGS_VIA_FILE_PYINSTALLER = OPENVPN_SERVER_ARGS + ['--auth-user-pass-verify',
                                                                  AUTH_SCRIPT_PATH_PYINSTALLER,
                                                                  'via-file']
OPENVPN_SERVER_ARGS_VIA_ENV_PYINSTALLER = OPENVPN_SERVER_ARGS + ['--auth-user-pass-verify',
                                                                 AUTH_SCRIPT_PATH_PYINSTALLER,
                                                                 'via-env']
OPENVPN_SERVER_ARGS_C_PLUGIN = OPENVPN_SERVER_ARGS + ['--plugin', '/usr/lib/openvpn/openvpn-auth-ldap.so',
                                                      OPENVPN_SERVER_LDAP_C_CONFIG_PATH, 'login',
                                                      '--username-as-common-name']
OPENVPN_CLIENT_ARGS = (
    '--client', '--dev', 'tun', '--verb', '5', '--proto', 'udp', '--remote', '127.0.0.1',
    str(OPENVPN_SERVER_PORT),
    '--nobind', '--ifconfig-noexec', '--route-noexec', '--route-nopull', '--ca', OPENVPN_SERVER_CA_FILE,
    '--auth-user-pass', '--explicit-exit-notify', '1', '--keepalive', '10', '120',
)
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
CONFIG_C = f"""<LDAP>
	URL		"{LDAP_URL}"
	BindDN		{LDAP_ADMIN_DN}
	Password	{LDAP_ADMIN_PASSWORD}
	Timeout		15
	TLSEnable	no
	FollowReferrals yes
</LDAP>
<Authorization>
    BaseDN		"{LDAP_BASE_DN}"
    SearchFilter	"(uid=%u)"
    RequireGroup	false
    <Group>
      BaseDN		"{LDAP_BASE_DN}"
      SearchFilter	"(|(cn=developers)(cn=artists))"
      MemberAttribute	member
    </Group>
</Authorization>
"""

# CONSTANTS: TEST CREDENTIALS
TEST_USERNAME = 'testuser'
TEST_USER_DN_TEMPLATE = "uid={},{}"
TEST_USER_DN = TEST_USER_DN_TEMPLATE.format(TEST_USERNAME, LDAP_BASE_DN)
TEST_USER_PASSWORD = 'testpass'
TEST_USER_WRONG_PASSWORD = 'wrong_password'

# CONSTANTS: EXPECTED OPENVPN LOG FRAGMENTS
OPENVPN_LOG_SERVER_INIT_COMPLETE = 'Initialization Sequence Completed'
OPENVPN_LOG_CLIENT_INIT_COMPLETE = 'Initialization Sequence Completed'
OPENVPN_LOG_AUTH_SUCCEEDED_SERVER = 'authentication succeeded for username'
OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT = 'Initialization Sequence Completed'
OPENVPN_LOG_AUTH_FAILED_SERVER = 'verification failed for peer'
OPENVPN_LOG_AUTH_FAILED_CLIENT = 'AUTH_FAILED'

# CONSTANTS: BENCHMARK CSV
BENCHMARK_CSV_HEADER_LABEL = 'label'
BENCHMARK_CSV_HEADER_PYTHON = 'python_version'
BENCHMARK_CSV_HEADER_OPENVPN = 'openvpn_version'
BENCHMARK_CSV_HEADER_LOGINS = 'concurrent_logins'
BENCHMARK_CSV_HEADER_MIN = 'min'
BENCHMARK_CSV_HEADER_MAX = 'max'
BENCHMARK_CSV_HEADER_AVG = 'avg'
BENCHMARK_CSV_HEADERS = (BENCHMARK_CSV_HEADER_LABEL, BENCHMARK_CSV_HEADER_PYTHON, BENCHMARK_CSV_HEADER_OPENVPN,
                         BENCHMARK_CSV_HEADER_LOGINS, BENCHMARK_CSV_HEADER_MIN, BENCHMARK_CSV_HEADER_MAX,
                         BENCHMARK_CSV_HEADER_AVG)
