#!/bin/sh

#
# Usage: ./dsg.sh "test message" pid ...
#
set -eu

: ${DEST:="."}
: ${COORD:="ws://localhost:8080/v1/msg-relay"}
: ${COORD2:=${COORD}}

T=${1}; shift
public_key=${1}; shift
message=${1}; shift

pids="$@"

cmd="cargo run -p dkls-party --release -q --"

date

instance=$(openssl rand -hex 32)

pks=""
sks=""
for p in ${pids}; do
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    pks="${pks} --party ${_pk}"
    sks="${sks} --party ${DEST}/party_${p}_sk:${DEST}/keyshare.${p}"
done

nodes=""
for p in $(jot ${T} 8081); do
    nodes="${nodes} --node http://localhost:${p}/"
done

# Create a setup message for DSG.
$cmd sign-setup \
     --instance ${instance} \
     --ttl 10 \
     --sign ${DEST}/setup_sk \
     --public-key ${public_key} \
     --message "${message}" --hash-fn SHA256 \
     --coordinator ${COORD} \
     ${pks} \
     ${nodes}
