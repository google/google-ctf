#!/bin/bash

if [ -f /pow ]; then
  POW="$(cat /pow)"
  if [ ${POW} != 0 ]; then
    if ! /usr/bin/pow.py ask "${POW}"; then
      echo 'pow fail'
      exit 1
    fi
  fi
fi

exec "$@"
