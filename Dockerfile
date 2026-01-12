FROM rust:1.76 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/stateset-ucp-handler /usr/local/bin/ucp-handler
EXPOSE 8081
CMD ["/usr/local/bin/ucp-handler"]
