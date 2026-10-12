import csv
import os

import pytest
import yaml
from ldap.ldapobject import SimpleLDAPObject

from tests.system.constants import (
    BENCHMARK_CSV_HEADER_AVG,
    BENCHMARK_CSV_HEADER_LABEL,
    BENCHMARK_CSV_HEADER_MAX,
    BENCHMARK_CSV_HEADER_MIN,
    BENCHMARK_CSV_HEADERS,
    BENCHMARK_DIR,
    LDAP_BASE_DN,
    OPENVPN_SERVER_LDAP_C_CONFIG_PATH,
    OPENVPN_SERVER_LDAP_CONFIG_PATH,
    OPENVPN_VERSION,
    PYTHON_VERSION,
    TEST_USER_DN,
    TEST_USER_DN_TEMPLATE,
    TEST_USER_PASSWORD,
    TEST_USERNAME,
)
from tests.system.utils import (
    Process,
    create_user,
    delete_user,
    init_ldap_connection,
    run_openvpn_server_with_args,
)


@pytest.fixture
def connection() -> SimpleLDAPObject:
    return init_ldap_connection()


@pytest.fixture(autouse=True)
def create_test_user(connection: SimpleLDAPObject):
    create_user(connection, TEST_USER_DN, TEST_USER_PASSWORD)


@pytest.fixture
def test_users(request, connection: SimpleLDAPObject) -> list[tuple[str, str]]:
    users = []
    for user_id in range(request.param):
        username = TEST_USERNAME + str(user_id)
        password = TEST_USER_PASSWORD + str(user_id)
        create_user(connection, TEST_USER_DN_TEMPLATE.format(username, LDAP_BASE_DN), password)
        users.append((username, password))
    yield users
    for username, _ in users:
        delete_user(connection, TEST_USER_DN_TEMPLATE.format(username, LDAP_BASE_DN))


@pytest.fixture
def openvpn_server(request) -> Process:
    process = run_openvpn_server_with_args(request.param)
    yield process
    process.terminate()


@pytest.fixture
def config(request) -> Process:
    with open(OPENVPN_SERVER_LDAP_CONFIG_PATH, "w") as f:
        f.write(yaml.dump(request.param))
    yield request.param
    os.remove(OPENVPN_SERVER_LDAP_CONFIG_PATH)


@pytest.fixture
def config_c_plugin(request) -> Process:
    with open(OPENVPN_SERVER_LDAP_C_CONFIG_PATH, "w") as f:
        f.write(request.param)
    yield request.param
    os.remove(OPENVPN_SERVER_LDAP_C_CONFIG_PATH)


@pytest.fixture(scope="session")
def benchmark_result_file() -> str:
    os.makedirs(BENCHMARK_DIR, exist_ok=True)
    path = os.path.join(BENCHMARK_DIR, "results.csv")
    with open(path, "w+", newline="") as results_csv_file:
        writer = csv.DictWriter(results_csv_file, fieldnames=BENCHMARK_CSV_HEADERS)
        writer.writeheader()
    yield path
    with open(path, newline="") as results_csv_file:
        rows = sorted(
            csv.DictReader(results_csv_file), key=lambda row: float(row[BENCHMARK_CSV_HEADER_AVG])
        )
    lines = [
        f"### Python {PYTHON_VERSION} & OpenVPN {OPENVPN_VERSION}",
        "",
        "| Authenticator | avg [s] | min [s] | max [s] |",
        "|---|---:|---:|---:|",
    ]
    lines += [
        f"| {row[BENCHMARK_CSV_HEADER_LABEL]} | {float(row[BENCHMARK_CSV_HEADER_AVG]):.2f} "
        f"| {float(row[BENCHMARK_CSV_HEADER_MIN]):.2f} "
        f"| {float(row[BENCHMARK_CSV_HEADER_MAX]):.2f} |"
        for row in rows
    ]
    with open(os.path.splitext(path)[0] + ".md", "w") as summary_file:
        summary_file.write("\n".join(lines) + "\n")
