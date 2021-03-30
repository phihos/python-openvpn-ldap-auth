#!/usr/bin/env bash
poetry install
poetry run pyinstaller -F $(poetry env info -p)/bin/openvpn-ldap-auth
