FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

ADD . /horusec
WORKDIR /horusec

RUN env GOOS=linux GOARCH=amd64 go build -o /bin/horusec ./horusec-cli/cmd/horusec/main.go

FROM docker:18-dind

COPY --from=builder /bin/horusec /usr/bin
RUN chmod +x /usr/bin/horusec
