// Copyright 2020 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package relational

import (
	"github.com/ZupIT/horusec/development-kit/pkg/utils/repository/response"
	"gorm.io/gorm"
)

type InterfaceRead interface {
	Connect(dialect, uri string, logMode bool) *response.Response
	GetConnection() *gorm.DB
	IsAvailable() bool
	SetLogMode(logMode bool)
	Find(entity interface{}, query *gorm.DB, tableName string) *response.Response
	SetFilter(filter map[string]interface{}) *gorm.DB
	First(out interface{}, tableName string, where ...interface{}) *response.Response
	RawSQL(sql string, entity interface{}) *response.Response
}
