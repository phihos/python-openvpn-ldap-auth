# Python OpenVPN LDAP Auth

[![PyPI license](https://img.shields.io/pypi/l/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
[![PyPI status](https://img.shields.io/pypi/status/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
[![PyPI version shields.io](https://img.shields.io/pypi/v/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
![main build status](https://github.com/phihos/Python-OpenVPN-LDAP-Auth/actions/workflows/test.yml/badge.svg?branch=main)

An auth verify script for [OpenVPN](https://community.openvpn.net) to authenticate via LDAP. Each VPN login is
forwarded to this script and the script in turn attempts a simple bind against the specified LDAP server. When the bind
is successful the script returns exit code 0 telling OpenVPN that the credentials are valid.

Although there already is the [openvpn-auth-ldap](https://github.com/threerings/openvpn-auth-ldap) plugin I felt the
need to write this auth script. First the source code is more accessible due to it being written in Python. Second it
offers more possibilities regarding
OpenVPN's [`static-challenge`](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/) parameter (see
below).

The downsides of using a script instead of a C-plugin
are [less performance and slightly reduced security](https://openvpn.net/community-resources/using-alternative-authentication-methods/).
If you are fine with that go ahead.

## Quickstart

Install the package via pip:

```shell
pip install openvpn-ldap-auth
```

Then create `/etc/openvpn/ldap.yaml`:

```yaml
ldap:
  url: 'ldaps://first.ldap.tld:636/ ldaps://second.ldap.tld:636/'
  bind_dn: 'uid=readonly,dc=example,dc=org'
  password: 'somesecurepassword'
  timeout: 5 # optional
authorization:
  base_dn: 'ou=people,dc=example,dc=org'
  search_filter: '(uid={})' # optional, {} will be replaced with the username
  static_challenge: 'ignore' # optional, other values are prepend, append 
```

Find out where `openvpn-ldap-auth` lives:

```shell
which openvpn-ldap-auth
```

Add the following line to your OpenVPN server configuration:

```
script-security 2
auth-user-pass-verify /path/to/openvpn-ldap-auth via-file
```

Now you can start your OpenVPN server and try to connect with a client.

## Installation

### Single Executable

For those who wish to [sacrifice a little more performance](https://pyinstaller.readthedocs.io/en/stable/operating-mode.html#how-the-one-file-program-works) for not having to install or compile a Python interpreter or you just want to quickly try the script out this option might be interesting.
Each [release](https://github.com/phihos/python-openvpn-ldap-auth/releases) also has executables attached to it: *openvpn-ldap-auth-&lt;distro&gt;-&lt;distro-version&gt;-&lt;arch&gt;*. They are created via [PyInstaller](https://www.pyinstaller.org/) on the respective Linux distro, version and architecture. They might also work on other distros provided they use the same or a later libc version that the distro uses.

**Important: /tmp must not be read only.**

### From Source

Download or clone this repository, cd into it and run

```shell
pip install poetry
poetry install --no-dev
poetry build
pip install --upgrade --find-links=dist openvpn-ldap-auth
```

Exchange `pip` with `pip3` if applicable.

## Configuration

### Static Challenge

If you want users to provide a normal password combined with a one-time-password OpenVPN's
[`static-challenge`](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/) parameter is what you
are looking for.

In the client configuration you need to add a line like

```
static-challenge "Enter OTP" 1 # use 0 if the OTP should not be echoed
```

When connecting you will now be prompted for your password and your OTP. By setting `authorization.static_challenge` you
can now influence how the OTP is used:

- *ignore (default)*: Just use the password for binding.
- *prepend*: Prepend the OTP to your password and use that for binding.
- *append*: Append the OTP to your password and use that for binding.

The last two options are useful if your LDAP server offers internal 2FA validation 
like [oath-ldap](https://oath-ldap.stroeder.com/).

### Using `via-env`

In the server configuration the following alternative setting is also supported but discouraged:

```
auth-user-pass-verify /path/to/openvpn-ldap-auth via-env
```

OpenVPN's manpage about that topic:

*If method is set to "via-env", OpenVPN will call script with the environmental variables username and password set to 
the username/password strings provided by the client. Be aware that this method is insecure on some platforms which 
make the environment of a process publicly visible to other unprivileged processes.*

If you still want to use `via-env` make sure to set `script-security` to `3`.

## Running Tests

First make sure to install [Docker](https://docs.docker.com/engine/install/)
with [docker-compose](https://docs.docker.com/compose/install/)
and [tox](https://tox.readthedocs.io/en/latest/install.html). Then run

```shell
tox
```

To run a specific Python-OpenVPN combination run something like

```shell
tox -e python38-openvpn25
```

To see a full list of current environment see the `tool.tox` section in [pyproject.toml](pyproject.toml).
