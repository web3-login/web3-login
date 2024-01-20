FROM rust:1.73.0-slim-buster AS builder
WORKDIR /usr/src/

RUN USER=root cargo new web3-login
WORKDIR /usr/src/web3-login
RUN touch src/lib.rs
COPY Cargo.toml Cargo.lock ./
RUN cargo fetch
RUN rm src/*.rs
COPY src ./src
COPY static ./static
RUN touch src/bin/main.rs
RUN touch src/lib.rs
RUN cargo build --features=cli --release

FROM rust:1.73.0-slim-buster

COPY --from=builder /usr/src/web3-login/target/release/web3-login /bin
USER 1000
ENTRYPOINT [ "web3-login" ]