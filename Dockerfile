FROM rust:1.72 as builder

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=secret,id=token \
    set -e; \
    rustup target add wasm32-unknown-unknown; \
    cargo install wasm-opt; \
    cargo install wasm-pack

WORKDIR /src
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=secret,id=token \
    set -e; \
    git config --global credential.helper store; \
    echo "https://docker:$(cat /run/secrets/token)@gitlab.com" > ~/.git-credentials; \
    cargo build -p dkls-party -p msg-relay-svc --release; \
    wasm-pack build -t web wrapper/wasm

FROM node:18-bookworm-slim as web

RUN apt-get update -y && apt-get install -y openssl

WORKDIR /src
COPY . .
COPY --from=builder /src/wrapper/wasm/pkg ./wrapper/wasm/pkg

RUN set -ex; cd wrapper/wasm/demo; \
    npm install; npm run build

FROM node:18-bookworm-slim

RUN apt-get update -y && apt-get install -y openssl caddy curl

WORKDIR /app

COPY ./testdata ./data
RUN    mkdir -p ./data/node-0 \
    && mkdir -p ./data/node-1 \
    && mkdir -p ./data/node-2

COPY --from=web     /src/wrapper/wasm/demo            ./demo
COPY --from=builder /src/target/release/dkls-party    /usr/local/bin/dkls-party
COPY --from=builder /src/target/release/msg-relay-svc /usr/local/bin/msg-relay-svc

ENV PORT=8080
ENV BODY_SIZE_LIMIT=5000000

CMD ["/usr/local/bin/node", "./demo/build"]
