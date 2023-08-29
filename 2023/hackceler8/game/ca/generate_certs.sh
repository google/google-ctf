#!/usr/bin/env bash
set -euo pipefail

# 1024 / 2048 / 4096
KEY_LENGTH=2048
TEAMS=("_MMM_" "DiceGang" "Blue Water" "Kalmarunionen" "WreckZeroBytes" "C4T BuT S4D" "Dragon Sector" "organizers")

CA_CERT="CA-devel.crt"
CA_KEY="CA-devel.key"

function generate_cert {
  if [ "$#" -ne 2 ]; then
    echo "Invalid argument count"
    exit 1
  fi;
  local CN=$1
  local FILENAME=$2

  echo "Generating '${FILENAME}.crt' with CN = '${CN}'"

  if [[ -f "${FILENAME}.key" ]]; then
    echo "${FILENAME}.key already exists, skipping";
    return;
  fi;

  openssl req \
    -batch \
    -newkey rsa:${KEY_LENGTH} \
    -nodes \
    -subj "/CN=${CN}/" \
    -keyout "${FILENAME}.key" \
    -out "${FILENAME}.csr"

  openssl x509 \
    -req \
    -days 30 \
    -in "${FILENAME}.csr" \
    -out "${FILENAME}.crt" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    && rm "${FILENAME}.csr"
}

if [[ ! -f "${CA_CERT}" ]]; then
  echo "CA cert missing" 
  exit 1
fi;

if [[ ! -f "${CA_KEY}" ]]; then
  echo "CA key missing" 
  exit 1
fi;

mkdir -p teams

# Generate team certificates
for team_nr in "${!TEAMS[@]}"; do
  team=${TEAMS[${team_nr}]}
  generate_cert "team${team_nr}" "teams/${team}"
done;

# Generate server certificate
generate_cert "prod-server" "prod-server"

