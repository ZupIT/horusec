FROM golang:alpine AS builder

RUN apk update && apk add --no-cache git

ADD . /go/src/github.com/ZupIT/horusec
WORKDIR /go/src/github.com/ZupIT/horusec
COPY . .

RUN env GOOS=linux GOARCH=amd64 go build -o /bin/horusec-kotlin ./horusec-kotlin/cmd/app/main.go

FROM golang:alpine

COPY --from=builder /bin/horusec-kotlin /bin/horusec-kotlin
RUN chmod +x /bin/horusec-kotlin

