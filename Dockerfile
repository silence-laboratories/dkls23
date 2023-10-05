FROM rust:1.72 as builder

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=secret,id=token \
    set -e; \
    git config --global credential.helper store; \
    echo "https://docker:$(cat /run/secrets/token)@gitlab.com" > ~/.git-credentials; \
    cargo build -p dkls-party -p msg-relay-svc --release; \
    cargo build --example dkg --release; \
    cargo build --example dsg --release; \
    cargo build --example vsot --release

FROM debian:12

RUN apt-get update -y && apt-get install -y openssl

WORKDIR /app

COPY --from=builder /src/target/release/dkls-party    /usr/local/bin/dkls-party
COPY --from=builder /src/target/release/msg-relay-svc /usr/local/bin/msg-relay-svc

COPY --from=builder /src/target/release/examples/dkg  /usr/local/bin/dkg
COPY --from=builder /src/target/release/examples/dsg  /usr/local/bin/dsg
COPY --from=builder /src/target/release/examples/vsot /usr/local/bin/vsot
