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

$cmd gen-party-keys ${DEST}/setup_sk

all_party_sk=""
all_party_pk=""
for p in $(jot ${N} 0); do
    $cmd gen-party-keys ${DEST}/party_${p}_sk
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    eval party_${p}_pk=${_pk}
    all_party_pk="${all_party_pk} --party ${_pk}"
    all_party_sk="${all_party_sk} --party ${DEST}/party_${p}_sk"
done

# echo ${all_party_pk}
# echo ${all_party_sk}

instance=$(openssl rand -hex 32)

#
# Create a setup message
#
$cmd keygen-setup \
     --instance ${instance} \
     --ttl 1000 \
     --threshold ${T} \
     --sign ${DEST}/setup_sk \
     --output ${DEST}/keygen-setup.msg \
     ${all_party_pk}

echo "keygen start $(date)"
$cmd key-gen \
     --setup ${DEST}/keygen-setup.msg \
     --prefix ${DEST} \
     --setup-vk $( $cmd load-party-keys ${DEST}/setup_sk --public ) \
     --instance ${instance} \
     --coordinator ${COORD} \
     ${all_party_sk}
echo "keygen end   $(date)"

$cmd share-pubkey ${DEST}/keyshare.0
