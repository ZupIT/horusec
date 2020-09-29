FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git build-base

ADD . /horusec

WORKDIR /horusec

RUN GOOS=linux go build -a -o horusec-messages-main ./horusec-messages/cmd/app/main.go

FROM alpine

COPY --from=builder /horusec/horusec-messages-main .

ENTRYPOINT ["./horusec-messages-main"]