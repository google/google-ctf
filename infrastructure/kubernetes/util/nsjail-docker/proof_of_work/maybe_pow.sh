#!/bin/bash

if [ -f /config/pow ]; then
  POW="$(cat /config/pow)"
  if [ ${POW} != 0 ]; then
    if ! /usr/bin/pow.py ask "${POW}"; then
      echo 'pow fail'
      exit 1
    fi
  fi
fi

exec "$@"
