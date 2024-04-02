#!/usr/bin/env bash
set -e
poetry install
poetry
PKG_NAME=$(poetry version | awk '{print $1}' | sed 's/-/_/g')
PKG_VERSION=$(poetry version | awk '{print $2}')
wheel2deb -v --search-path ./dist
