FROM golang:alpine as builder

RUN apk update && apk upgrade \
	&& apk add --no-cache alpine-sdk bash make git 

RUN git clone https://github.com/src-d/enry.git && cd enry && make build 

# From the base image
FROM alpine:3.8

RUN apk update && apk upgrade \
	&& apk add --update --no-cache git openssh-client
COPY --from=builder /go/enry/build/bin/enry /usr/bin/