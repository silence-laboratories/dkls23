#!/bin/sh

#
# Usage: ./dsg.sh "test message" pid ...
#
set -e

: ${DEST:="."}
: ${COORD:="ws://localhost:8080/v1/msg-relay"}
: ${COORD2:=${COORD}}

message=${1}
shift

pids="$@"

cmd="cargo run -p dkls-party --release -q --"
# cmd="/usr/local/bin/dkls-party"

date

instance=$(openssl rand -hex 32)
public_key=$($cmd share-pubkey ${DEST}/keyshare.0)

pks=""
sks=""
for p in ${pids}; do
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    pks="${pks} --party ${_pk}"
    sks="${sks} --party ${DEST}/party_${p}_sk:${DEST}/keyshare.${p}"
done

# Create a setup message for DSG.
$cmd sign-setup \
     --instance ${instance} \
     --ttl 10 \
     --sign ${DEST}/setup_sk \
     --public-key ${public_key} \
     --message "${message}" --hash-fn SHA256 \
     --coordinator ${COORD} \
     ${pks}

# Execute T parties to generate a signature.
$cmd sign-gen \
     --instance ${instance} \
     --setup-vk $( $cmd load-party-keys ${DEST}/setup_sk --public ) \
     --coordinator ${COORD2} \
     --prefix ${DEST} \
     ${sks}
