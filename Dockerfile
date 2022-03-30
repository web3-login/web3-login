FROM rust:1.56.0-slim-buster AS builder
WORKDIR /usr/src/

RUN USER=root cargo new web3-login
WORKDIR /usr/src/web3-login
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release
RUN rm src/*.rs
COPY src ./src
COPY static ./static
RUN touch src/main.rs
RUN cargo build --release

FROM rust:1.56.0-slim-buster

COPY --from=builder /usr/src/web3-login/target/release/web3-login /bin
USER 1000
CMD [ "web3-login" ]