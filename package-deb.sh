#!/usr/bin/env bash
set -e
poetry install
poetry build -f sdist
PKG_NAME=$(poetry version | awk '{print $1}')
PKG_VERSION=$(poetry version | awk '{print $2}')
poetry run py2dsc-deb "dist/${PKG_NAME}-${PKG_VERSION}.tar.gz"
