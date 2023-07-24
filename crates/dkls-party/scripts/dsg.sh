 #!/bin/sh

set -ex

: ${COORD:="https://coord.fly.dev"}

cmd="cargo run -p dkls-party --release --"

date

t=${1}; shift
n=${1}; shift
m=${1}; shift

prefix="${t}x${n}"

sids=$($cmd sign-sess --t ${t} --message ${m} --coordinator ${COORD})


parties=""
for sid in ${sids}; do
    # $cmd party-keys party-keys-${sid}
    # parties="${parties} --party ${sid}:share-${sid}:party-keys-${sid}"
    share=${1}; shift
    parties="${parties} --party ${sid}:${share}:sign-${sid}"
done

$cmd sign-gen --t ${t} --message ${m} ${parties} --coordinator ${COORD}

date
