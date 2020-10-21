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

sed -i -e "s/window.REACT_APP_HORUSEC_ENDPOINT_API=\"\"/window.REACT_APP_HORUSEC_ENDPOINT_API=\"$REACT_APP_HORUSEC_ENDPOINT_API\"/g" "/var/www/index.html"
sed -i -e "s/window.REACT_APP_HORUSEC_ENDPOINT_ANALYTIC=\"\"/window.REACT_APP_HORUSEC_ENDPOINT_ANALYTIC=\"$REACT_APP_HORUSEC_ENDPOINT_ANALYTIC\"/g" "/var/www/index.html"
sed -i -e "s/window.REACT_APP_HORUSEC_ENDPOINT_ACCOUNT=\"\"/window.REACT_APP_HORUSEC_ENDPOINT_ACCOUNT=\"$REACT_APP_HORUSEC_ENDPOINT_ACCOUNT\"/g" "/var/www/index.html"

nginx -g "daemon off;"
