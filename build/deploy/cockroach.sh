#!/bin/sh

set -eu

if [ -f ./test.sh ]; then
  ./test.sh || exit $?
fi
if [ "${1:-}" = "shell" ]; then
  /bin/bash "$@"
else
  /cockroach/cockroach "$@"
fi
