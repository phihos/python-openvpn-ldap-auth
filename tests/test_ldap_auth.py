import pytest
from ldap.ldapobject import SimpleLDAPObject

from tests.constants import TEST_TIMEOUT, TEST_USER_PASSWORD, \
    OPENVPN_SERVER_ARGS_VIA_ENV, OPENVPN_SERVER_ARGS_VIA_FILE, \
    CONFIG_CHALLENGE_RESPONSE_IGNORE, CONFIG_CHALLENGE_RESPONSE_PREPEND, CONFIG_CHALLENGE_RESPONSE_APPEND, \
    OPENVPN_CLIENT_ARGS_WITH_CHALLENGE, TEST_USERNAME, OPENVPN_LOG_AUTH_SUCCEEDED_SERVER, \
    OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT, OPENVPN_CLIENT_ARGS_WITHOUT_CHALLENGE, TEST_USER_WRONG_PASSWORD, \
    OPENVPN_LOG_AUTH_FAILED_CLIENT, OPENVPN_LOG_AUTH_FAILED_SERVER
from tests.utils import Process, OpenVPNProcess


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
