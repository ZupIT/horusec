#! /bin/bash
# Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


MIGRATION_PATH="./development-kit/pkg/databases/relational/migration"
POSTGRES_USER="root"
POSTGRES_PASSWORD="root"
POSTGRES_HOST="localhost"
POSTGRES_PORT="5432"
POSTGRES_DB_NAME="horusec_db"
POSTGRES_SSL_MODE="disable"
MIGRATE_TYPE=$1
MIGRATE_NUMBERS=$2

runMigration() {
    if [[ -z "$MIGRATE_TYPE" ]]
    then
        echo "Migration type param not found. Setup default \"up\""
        MIGRATE_TYPE="up"
    fi

    docker run --name migrate \
        --rm -v "$(pwd)/$MIGRATION_PATH:/migrations" \
        --network=container:postgresql migrate/migrate:v4.13.0 \
        -path=/migrations/ \
        -database postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@$POSTGRES_HOST:$POSTGRES_PORT/$POSTGRES_DB_NAME?sslmode=$POSTGRES_SSL_MODE \
        $MIGRATE_TYPE "$MIGRATE_NUMBERS"
}

runMigration