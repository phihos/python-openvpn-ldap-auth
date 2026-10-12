ARG python_version

FROM python:${python_version}

ARG openvpn_version

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv

# install openvpn from the official OpenVPN repository
RUN CODENAME=$(. /etc/os-release && echo "$VERSION_CODENAME") && \
    wget -qO /usr/share/keyrings/openvpn-repo.gpg https://swupdate.openvpn.net/repos/repo-public.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/openvpn-repo.gpg] https://build.openvpn.net/debian/openvpn/release/$openvpn_version $CODENAME main" \
      > /etc/apt/sources.list.d/openvpn-aptrepo.list
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq --no-install-recommends \
      openvpn openvpn-auth-ldap libsasl2-dev libldap2-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# The venv lives outside /project because the source tree gets bind-mounted over it.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    PATH=/opt/venv/bin:$PATH
WORKDIR /project
COPY pyproject.toml uv.lock /project/
RUN uv sync --frozen --no-install-project
