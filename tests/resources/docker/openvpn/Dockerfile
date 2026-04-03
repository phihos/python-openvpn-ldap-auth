ARG python_version

FROM python:${python_version}

ARG openvpn_version

# install openvpn from the official OpenVPN repository
RUN CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME") && \
    wget -qO /usr/share/keyrings/openvpn-repo.gpg https://swupdate.openvpn.net/repos/repo-public.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/openvpn-repo.gpg] http://build.openvpn.net/debian/openvpn/release/$openvpn_version $CODENAME main" \
      > /etc/apt/sources.list.d/openvpn-aptrepo.list && \
    cat /etc/apt/sources.list.d/openvpn-aptrepo.list
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq openvpn libsasl2-dev python3-dev libldap2-dev \
                                                        libssl-dev openvpn-auth-ldap

# prepare environment
RUN pip install poetry poetry-plugin-export
RUN mkdir /project
WORKDIR /project
COPY pyproject.toml poetry.lock README.md /project/
COPY openvpn_ldap_auth /project/openvpn_ldap_auth
RUN poetry export --without-hashes -f requirements.txt --output requirements.txt
RUN pip install  -r requirements.txt
RUN poetry install
