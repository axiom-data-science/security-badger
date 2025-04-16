FROM rust:1.86-alpine3.21

# Metadata
LABEL org.opencontainers.image.authors="Luke Campbell <luke@axds.co>"
LABEL org.opencontainers.image.url="https://git.axiom/axiom/security-badger/"
LABEL org.opencontainers.image.source="https://git.axiom/axiom/security-badger/"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache musl-dev && apk cache clean

# Build the release binary
WORKDIR /opt/security-badger
COPY src ./src
COPY README.md LICENSE Cargo.toml ./
RUN cargo build --release

# Copy release binary to fresh buster-slim image
FROM alpine:3.21
RUN apk add --no-cache musl-dev && apk cache clean
COPY --from=0 /opt/security-badger/target/release/security-badger /usr/bin/security-badger
ENTRYPOINT ["/usr/bin/security-badger"]
