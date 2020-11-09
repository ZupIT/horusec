#!/bin/sh
migrate -path "/horusec-migrations" -database "$HORUSEC_DATABASE_SQL_URI" up "$@" 
