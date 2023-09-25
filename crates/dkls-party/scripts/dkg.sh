#!/bin/sh

#
# Usage ./dkg.sh 5 3
#
# Generate key: threshold 3, partcipants 5
#

set -eu

: ${DEST:="."}

COORD=${3:-"ws://localhost:8080/v1/msg-relay"}
COORD2=${4:-${COORD}}

N=${1:-3}
T=${2:-2}

cmd="cargo run -p dkls-party -q --release -- "

# Some common abbrevs:
#
# SK - secret key. Also known as private key
#
# PK - public key. Also known as verification key.
#

# Parties communicates by publishing messages
# usig message relay service. All messages are
# authenticated. Digital signature is one of
# ways to authenticate a message.
#
# For broadcast messages (that without a designated
# receiver) we use ed25519.

# There is an entity that craetes a setup message.
# This message contains all information requires to
# execute distributed key generation protocol.
# This message will be shared with all participants
# should be signed.

# the following command generate fresh secret key and
# saves it to ${DEST}/stup_sk
$cmd gen-party-keys ${DEST}/setup_sk
$cmd load-party-keys ${DEST}/setup_sk --public > ${DEST}/setup_vk

# The next step will be create SK/PK pairs for all
# parties. Each party has a unique index in range [0..N)
#
# We save secret key in file ${DEST}/party_${p}_sk where
# ${p} is party index (or ID) and set all_party_sk to a
# string like this:
#   --party ${DEST}/party_0_sk --party ${DEST}/party_1_sk ...
#
# and all_party_pk to string like this:
#   --party "hex string of public key of party 0" --party ....
#

all_party_sk=""
all_party_pk=""
for p in $(jot ${N} 0); do
    $cmd gen-party-keys ${DEST}/party_${p}_sk
    _pk=$( $cmd load-party-keys ${DEST}/party_${p}_sk --public )
    eval party_${p}_pk=${_pk}
    all_party_pk="${all_party_pk} --party ${_pk}"
    all_party_sk="${all_party_sk} --party ${DEST}/party_${p}_sk"
done

# Also we need a unique instance ID. This is a unique ID of
# a particular execution of DKG protocol.
#
# The SK/PK we generated above serves a identities of parties,
# They are long term data.
#
# Instance ID is one time ID.
#
instance=$(openssl rand -hex 32)

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
     ${all_party_pk}

# Following command will execute N parties. The parties
# communicate by reading and publishing messages to
# message relay (given by --coordinator option).
#
# Each party will receive setup message, validate it
# (checks signature using passed public key by option --setup-vk)
#
# Option --prefix defines where to save keyshare
#
echo "keygen start $(date)"
$cmd key-gen \
     --prefix ${DEST} \
     --setup-vk $( $cmd load-party-keys ${DEST}/setup_sk --public ) \
     --instance ${instance} \
     --coordinator ${COORD2} \
     ${all_party_sk}
echo "keygen end   $(date)"

# load keyshare of first party and output public key.
$cmd share-pubkey ${DEST}/keyshare.0
