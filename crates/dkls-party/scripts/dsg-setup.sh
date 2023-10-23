#!/bin/sh

#
# Usage: ./dsg-setup.sh public-key "test message" pid ...
#
set -eu

_b=$(dirname $0)

: ${DEST:="${_b}/../../../testdata"}
: ${COORD:="ws://localhost:8080/v1/msg-relay"}

public_key=${1}; shift
message=${1}; shift

pids="$@"

cmd="cargo run -p dkls-party --release -q --"

instance=$(openssl rand -hex 32)

T=0
pks=""
for p in ${pids}; do
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    pks="${pks} --party ${_pk}"
    T=$(( ${T} + 1))
done

nodes=""
for p in ${pids}; do
    nodes="${nodes} --node http://localhost:$(( 8081 + ${p}))/"
done

# Create a setup message for DSG.
$cmd sign-setup \
     --instance ${instance} \
     --ttl 10 \
     --sign ${DEST}/setup_sk \
     --public-key ${public_key} \
     --chain-path "m" \
     --message "${message}" --hash-fn SHA256 \
     --coordinator ${COORD} \
     ${pks} \
     ${nodes}
