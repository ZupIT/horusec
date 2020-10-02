FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

ADD . /horusec
WORKDIR /horusec

RUN env GOOS=linux GOARCH=amd64 go build -o /bin/horusec ./horusec-cli/cmd/horusec/main.go

FROM docker:19-dind

COPY --from=builder /bin/horusec /usr/local/bin
RUN chmod +x /usr/local/bin/horusec

COPY --from=builder /horusec/horusec-cli/deployments/horusec-cli.sh /usr/local/bin
RUN chmod +x /usr/local/bin/horusec-cli.sh

ENTRYPOINT [ "horusec-cli.sh" ]
CMD [ "sh" ]