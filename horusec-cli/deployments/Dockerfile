FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

ADD . /horusec
WORKDIR /horusec

RUN env GOOS=linux GOARCH=amd64 go build -o /bin/horusec ./horusec-cli/cmd/horusec/main.go

FROM alpine

COPY --from=builder /bin/horusec /usr/bin
RUN chmod +x /usr/bin/horusec

RUN apk add --no-cache ca-certificates curl openssl git openssh-client docker

ADD ./horusec-cli/deployments/docker-entrypoint.sh /usr/local/bin
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["sh"]