ARG python_version

FROM python:${python_version}-buster

ARG openvpn_version

# install openvpn
RUN wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|apt-key add -
RUN echo "deb http://build.openvpn.net/debian/openvpn/release/$openvpn_version buster main" > /etc/apt/sources.list.d/openvpn-aptrepo.list
RUN cat /etc/apt/sources.list.d/openvpn-aptrepo.list
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq openvpn libsasl2-dev python-dev libldap2-dev \
                                                        libssl-dev openvpn-auth-ldap

# prepare environment
RUN pip install poetry==1.1.15
RUN mkdir /project
WORKDIR /project
COPY pyproject.toml poetry.lock README.md /project/
COPY openvpn_ldap_auth /project/openvpn_ldap_auth
RUN poetry export --without-hashes -f requirements.txt --output requirements.txt
RUN pip install  -r requirements.txt
RUN poetry install
