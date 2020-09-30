FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

ADD . /horusec
WORKDIR /horusec

RUN env GOOS=linux GOARCH=amd64 go build -o /bin/horusec ./horusec-cli/cmd/horusec/main.go

FROM docker:dind

COPY --from=builder /bin/horusec /bin/horusec
RUN chmod +x /bin/horusec

ENTRYPOINT [ "/bin/sh" ]