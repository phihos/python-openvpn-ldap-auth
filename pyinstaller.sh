#!/usr/bin/env bash
poetry install
poetry run pyinstaller -F $(which openvpn-ldap-auth)
