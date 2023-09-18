#!/bin/sh

#
# Usage ./dkg.sh 5 3
#
# Generate key: threshold 3, partcipants 5
#

set -eu

: ${DEST:="."}

COORD=${3:-"ws://localhost:8080/v1/msg-relay"}

N=${1:-3}
T=${2:-2}

cmd="cargo run -p dkls-party -q --release -- "

all_party_sk=""
all_party_pk=""
for p in $(jot ${N} 0); do
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    eval party_${p}_pk=${_pk}
    all_party_pk="${all_party_pk} --party ${_pk}"
    all_party_sk="${all_party_sk} --party ${DEST}/party_${p}_sk"
done

instance=$(openssl rand -hex 32)

nodes=""
for p in $(jot ${N} 8081); do
    nodes="${nodes} --node http://localhost:${p}/"
done

# Now we are ready to generate and publish a setup message for
# distributed key generation. The setup message contains parameters
# N, T and PK of all parties that will participate in key generation.
# The message will be signed by given secret key a published to a
# given message relay (coordinator)
#
$cmd keygen-setup \
     --instance ${instance} \
     --ttl 10 \
     --threshold ${T} \
     --sign ${DEST}/setup_sk \
     --coordinator ${COORD} \
     ${all_party_pk} \
     ${nodes}
