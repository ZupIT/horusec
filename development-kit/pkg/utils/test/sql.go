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

package test

import (
	"github.com/ZupIT/horusec/development-kit/pkg/databases/relational"
)

type SQLUtil struct {
	databaseRead relational.InterfaceRead
}

type ISQLUtil interface {
	GetLast(out interface{})
}

func NewSQLUtil(databaseRead relational.InterfaceRead) ISQLUtil {
	return &SQLUtil{
		databaseRead: databaseRead,
	}
}

func (s *SQLUtil) GetLast(out interface{}) {
	s.databaseRead.GetConnection().Order("created_at desc").Limit(1).Find(out)
}
