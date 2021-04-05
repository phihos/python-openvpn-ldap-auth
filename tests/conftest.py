import csv
import os
from typing import Tuple, List

import plotly.graph_objects as go
import plotly.io as pio
import pytest
import yaml
from ldap.ldapobject import SimpleLDAPObject

from tests.constants import TEST_USER_DN, TEST_USER_PASSWORD, \
    OPENVPN_SERVER_LDAP_CONFIG_PATH, OPENVPN_SERVER_LDAP_C_CONFIG_PATH, BENCHMARK_DIR, BENCHMARK_CSV_HEADERS, \
    TEST_USERNAME, LDAP_BASE_DN, TEST_USER_DN_TEMPLATE, BENCHMARK_CSV_HEADER_LABEL, BENCHMARK_CSV_HEADER_AVG, \
    OPENVPN_VERSION, PYTHON_VERSION
from tests.utils import Process, create_user, run_openvpn_server_with_args, init_ldap_connection, delete_user

pio.orca.config.use_xvfb = True
pio.orca.config.save()


@pytest.fixture
def connection() -> SimpleLDAPObject:
    return init_ldap_connection()


@pytest.fixture(autouse=True)
def create_test_user(connection: SimpleLDAPObject):
    create_user(connection, TEST_USER_DN, TEST_USER_PASSWORD)


@pytest.fixture
def test_users(request, connection: SimpleLDAPObject) -> List[Tuple[str, str]]:
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
    with open(OPENVPN_SERVER_LDAP_CONFIG_PATH, 'w') as f:
        f.write(yaml.dump(request.param))
    yield request.param
    os.remove(OPENVPN_SERVER_LDAP_CONFIG_PATH)


@pytest.fixture
def config_c_plugin(request) -> Process:
    with open(OPENVPN_SERVER_LDAP_C_CONFIG_PATH, 'w') as f:
        f.write(request.param)
    yield request.param
    os.remove(OPENVPN_SERVER_LDAP_C_CONFIG_PATH)


@pytest.fixture(scope='session')
def benchmark_result_file() -> str:
    os.makedirs(BENCHMARK_DIR, exist_ok=True)
    path = os.path.join(BENCHMARK_DIR, f"results.csv")
    with open(path, 'w+', newline='') as results_csv_file:
        writer = csv.DictWriter(results_csv_file, fieldnames=BENCHMARK_CSV_HEADERS)
        writer.writeheader()
    yield path
    plot_x = []
    plot_y = []
    with open(path, 'r+', newline='') as results_csv_file:
        reader = csv.DictReader(results_csv_file)
        for row in reader:
            plot_x.append(row[BENCHMARK_CSV_HEADER_LABEL])
            plot_y.append(round(float(row[BENCHMARK_CSV_HEADER_AVG]), 2))

    fig = go.Figure(data=[go.Bar(x=plot_x, y=plot_y, text=plot_y, textposition='auto')])
    fig.update_xaxes(type='category', categoryorder='total ascending')
    fig.update_layout(
        title=f"Python {PYTHON_VERSION} & OpenVPN {OPENVPN_VERSION}",
        xaxis_title="LDAP Authenticators",
        yaxis_title="Time to authenticate a client in seconds",
    )
    fig.write_image(os.path.splitext(path)[0] + '.png')
