# Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
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

printf 'Generating Certs            ...'
rm -rf .env

if [ ! -f api/api-tls-cert.pem ] && [ ! -f api/api-tls-key.pem ]; then
    rm -rf deployments/certs/*
    ./deployments/scripts/create-certs.sh -m ca -pw "horusCertPassphrase" -t deployments/certs -e 900
    ./deployments/scripts/create-certs.sh -m server -h dockerapi -pw "horusCertPassphrase" -t deployments/certs -e 365
    ./deployments/scripts/create-certs.sh -m client -h horusapi -pw "horusCertPassphrase" -t deployments/certs -e 365
    ./deployments/scripts/create-certs.sh -m tls -h dockerapi -pw "horusCertPassphrase" -t api -e 365
fi

echo " done"
