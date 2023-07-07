#!/bin/sh

set -ex

# coord="https://gg19-coordinator.speedtest.magic.link"
coord="https://coord.fly.dev"
cmd="cargo run -p dkls-party --release --"

t=${1}
n=${2}
p=${3}

prefix="${p}${t}x${n}"

sids=$($cmd key-sess --t ${t} --n ${n} --lifetime 10 --coordinator ${coord} ) # two hours

parties=""
for sid in ${sids}; do
    parties="${parties} --party ${sid}:${prefix}-share-${sid}:"
done

RUST_LOG=info $cmd key-gen --t ${t} --n ${n} ${parties} --coordinator ${coord}
