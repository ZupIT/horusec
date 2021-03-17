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
MIGRATION_FILE_NAME=$1

createMigration() {
    if [[ -z "$MIGRATION_FILE_NAME" ]]
    then
        echo "Migration file name param not found."
    fi

    docker run --name migrate \
        migrate/migrate \
        -path=/migrations/ \
        create -ext sql -dir /migrations "$MIGRATION_FILE_NAME"
    docker cp migrate:/migrations $MIGRATION_PATH
    docker rm migrate
    mv $MIGRATION_PATH/migrations/* $MIGRATION_PATH/
    rm -rf "$MIGRATION_PATH/migrations"
}

createMigration
