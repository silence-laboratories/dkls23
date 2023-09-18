#!/bin/sh


set -eu

: ${DEST:="."}

N=${1:-3}

cmd="cargo run -p dkls-party -q --release -- "

$cmd gen-party-keys  ${DEST}/setup_sk
$cmd load-party-keys ${DEST}/setup_sk --public > ${DEST}/setup_vk

for p in $(jot ${N} 0); do
    $cmd gen-party-keys ${DEST}/party_${p}_sk
done

exit 0
