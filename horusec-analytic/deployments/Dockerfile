FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git build-base

ADD . /horusec

WORKDIR /horusec

RUN GOOS=linux go build -a -o horusec-analytic-main ./horusec-analytic/cmd/app/main.go

FROM alpine

COPY --from=builder /horusec/horusec-analytic-main .

ENTRYPOINT ["./horusec-analytic-main"]