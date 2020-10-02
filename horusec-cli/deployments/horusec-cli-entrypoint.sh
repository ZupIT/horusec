#!/bin/sh

/usr/local/bin/dockerd-entrypoint.sh &
sleep 5
horusec start "$@"