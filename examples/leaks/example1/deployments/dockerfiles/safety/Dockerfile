FROM python:3.6-alpine as builder

# Install and compile safety + its dependencies
RUN apk add --no-cache jq alpine-sdk bash openssh-client \
    && pip install safety

# Build a fresh container, copying across the compiled pieces
FROM python:3.6-alpine

COPY --from=builder /usr/local/lib/python3.6 /usr/local/lib/python3.6
COPY --from=builder /usr/local/bin/safety /usr/local/bin/safety

# Add packages that we need in the final image on runtime
RUN apk add --no-cache git jq bash openssh-client 
