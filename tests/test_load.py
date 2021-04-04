import concurrent.futures
import csv
import time
from timeit import default_timer as timer
from typing import Tuple, List

import pytest
from _pytest.outcomes import Failed
from ldap.ldapobject import SimpleLDAPObject

from tests.constants import CONFIG_CHALLENGE_RESPONSE_IGNORE, OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT, \
    OPENVPN_CLIENT_ARGS_WITHOUT_CHALLENGE, PYTHON_VERSION, \
    OPENVPN_VERSION, BENCHMARK_CSV_HEADERS, BENCHMARK_CSV_HEADER_PYTHON, BENCHMARK_CSV_HEADER_OPENVPN, \
    BENCHMARK_CSV_HEADER_MIN, BENCHMARK_CSV_HEADER_MAX, BENCHMARK_CSV_HEADER_AVG, OPENVPN_SERVER_ARGS_VIA_FILE, \
    BENCHMARK_CSV_HEADER_LABEL, BENCHMARK_CSV_HEADER_LOGINS, OPENVPN_SERVER_ARGS_C_PLUGIN, OPENVPN_SERVER_ARGS_VIA_ENV, \
    OPENVPN_SERVER_ARGS_VIA_FILE_PYINSTALLER, OPENVPN_SERVER_ARGS_VIA_ENV_PYINSTALLER, CONFIG_C
from tests.utils import Process, OpenVPNProcess


def login(openvpn_server: Process, username: str, password: str) -> float:
    """Log into VPN and return the time in seconds it took to perform authentication."""
    process = OpenVPNProcess(OPENVPN_CLIENT_ARGS_WITHOUT_CHALLENGE)
    process.enter_username_password(username, password)
    start = timer()
    try:
        process.check_in_output(OPENVPN_LOG_AUTH_SUCCEEDED_CLIENT, 65)
    except Failed as e:
        time.sleep(5)  # wait for auth output to appear in server log
        pytest.fail(f"{e}\n\nOpenVPN server Log:\n{openvpn_server.output()}\n\n")
    end = timer()
    process.terminate()
    return end - start


def benchmark(openvpn_server: Process, test_users: List[Tuple[str, str]]) -> Tuple[float, float, float]:
    benchmark_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(test_users)) as executor:
        futures = []
        for username, password in test_users:
            futures.append(executor.submit(login, openvpn_server, username, password))
        for future in concurrent.futures.as_completed(futures):
            try:
                benchmark_results.append(future.result())
            except Exception as exc:
                pytest.fail(f"A login process raised an exception: {exc}")
    return min(benchmark_results), max(benchmark_results), sum(benchmark_results) / len(benchmark_results)


@pytest.mark.parametrize("config_c_plugin", [CONFIG_C], indirect=True)
@pytest.mark.parametrize("openvpn_server,openvpn_server_label", [(OPENVPN_SERVER_ARGS_C_PLUGIN, 'C-Plugin'),
                                                                 (OPENVPN_SERVER_ARGS_VIA_FILE, 'Script via-file'),
                                                                 (OPENVPN_SERVER_ARGS_VIA_ENV, 'Script via-env'),
                                                                 (OPENVPN_SERVER_ARGS_VIA_FILE_PYINSTALLER,
                                                                  'PyInstaller via-file'),
                                                                 (OPENVPN_SERVER_ARGS_VIA_ENV_PYINSTALLER,
                                                                  'PyInstaller via-env'),
                                                                 ],
                         indirect=['openvpn_server'])
@pytest.mark.parametrize("config", [CONFIG_CHALLENGE_RESPONSE_IGNORE], indirect=True)
@pytest.mark.parametrize("test_users", [1], indirect=True)
def test_load_script(connection: SimpleLDAPObject, config_c_plugin, openvpn_server: Process, openvpn_server_label: str,
                     config: dict, benchmark_result_file: str, test_users: List[Tuple[str, str]]):
    # benchmark multiple times for a more reliable result
    measurements = []
    measurements.append(benchmark(openvpn_server, test_users))
    measurements.append(benchmark(openvpn_server, test_users))
    measurements.append(benchmark(openvpn_server, test_users))
    min_time = min(measurement[0] for measurement in measurements)
    max_time = max(measurement[1] for measurement in measurements)
    avg_time = sum(measurement[2] for measurement in measurements) / len(measurements)
    results = []
    with open(benchmark_result_file, 'r+', newline='') as results_csv_file:
        reader = csv.DictReader(results_csv_file, fieldnames=BENCHMARK_CSV_HEADERS)
        for row in reader:
            results.append(row)
    results.append({
        BENCHMARK_CSV_HEADER_LABEL: openvpn_server_label,
        BENCHMARK_CSV_HEADER_PYTHON: PYTHON_VERSION,
        BENCHMARK_CSV_HEADER_OPENVPN: OPENVPN_VERSION,
        BENCHMARK_CSV_HEADER_LOGINS: len(test_users),
        BENCHMARK_CSV_HEADER_MIN: min_time,
        BENCHMARK_CSV_HEADER_MAX: max_time,
        BENCHMARK_CSV_HEADER_AVG: avg_time,
    })
    with open(benchmark_result_file, 'w+', newline='') as results_csv_file:
        writer = csv.DictWriter(results_csv_file, fieldnames=BENCHMARK_CSV_HEADERS)
        writer.writerows(results)
