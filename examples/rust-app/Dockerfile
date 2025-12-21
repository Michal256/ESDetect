FROM rust:1.75 AS build
WORKDIR /usr/src/myapp
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
COPY --from=build /usr/local/cargo/bin/rust-app /usr/local/bin/rust-app
CMD ["rust-app"]
