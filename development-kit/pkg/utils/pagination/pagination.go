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

package pagination

import "math"

func GetSkip(page, size int64) int64 {
	var skip int64

	page--
	if page > 0 {
		skip = page * size
	}

	return skip
}

func GetTotalPages(paginationSize, totalItems int) int {
	if totalItems == 0 || paginationSize == 0 {
		return 0
	}

	return int(math.Ceil(float64(totalItems) / float64(paginationSize)))
}
