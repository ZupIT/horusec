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

// nolint
package main

import "fmt"

func main() {
	printPwd()
	connectWitDatabase()
}

func printPwd() {
	password := "password"

	print("This is an password" + password)
}

func connectWitDatabase() {
	URI := fmt.Sprint("postgresql://root:root@postgresql:5432/horusecDB?sslmode=disable")
	print(URI)
}
