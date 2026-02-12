# Minimal base image for static musl binary
FROM alpine:3.17

WORKDIR /app

# Copy the statically-linked binary
COPY ./target/x86_64-unknown-linux-musl/release/app /app/app

# Copy public keys (can be overridden via volume mount)
COPY ./loader.pub /app/loader.pub
COPY ./requester.pub /app/requester.pub

# Create directory for secrets (to be mounted at runtime)
RUN mkdir -p /app/keys

# Expose the server port
EXPOSE 4000

# Default entrypoint
# Users must provide --secret at runtime or mount a key file
ENTRYPOINT ["/app/app"]
CMD ["--ip-addr", "0.0.0.0:4000", "--secret", "/app/keys/id.sec", "--loader", "/app/loader.pub", "--requester", "/app/requester.pub"]
