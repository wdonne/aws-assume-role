FROM alpine:3.9.6 AS builder
ARG TARGETPLATFORM
COPY target/aarch64-unknown-linux-musl/release/aws-assume-role /target/aarch64-unknown-linux-musl/release/
COPY target/x86_64-unknown-linux-musl/release/aws-assume-role /target/x86_64-unknown-linux-musl/release/
RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
    cp /target/aarch64-unknown-linux-musl/release/aws-assume-role /aws-assume-role; \
    elif [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
    cp /target/x86_64-unknown-linux-musl/release/aws-assume-role /aws-assume-role; \
    fi
RUN apk add ca-certificates && update-ca-certificates

FROM scratch
USER 11000:11000
COPY --from=builder /aws-assume-role /app/
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
ENTRYPOINT ["/app/aws-assume-role"]
