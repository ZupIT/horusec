FROM alpine:latest

RUN apk add elixir git

RUN mix local.hex --force
RUN mix local.rebar --force
RUN mix escript.install hex mix_audit --force

RUN mv ./root/.mix/escripts/mix_audit ./bin/
