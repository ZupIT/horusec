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

//nolint
package dashboard

import "github.com/graphql-go/graphql"

func createAnalysisType() *graphql.Object {
	return graphql.NewObject(graphql.ObjectConfig{Name: "analysis", Fields: graphql.Fields{
		"repositoryID": &graphql.Field{
			Type: graphql.String,
		},
		"repositoryName": &graphql.Field{
			Type: graphql.String,
		},
		"companyID": &graphql.Field{
			Type: graphql.String,
		},
		"companyName": &graphql.Field{
			Type: graphql.String,
		},
		"status": &graphql.Field{
			Type: graphql.String,
		},
		"errors": &graphql.Field{
			Type: graphql.String,
		},
		"createdAt": &graphql.Field{
			Type: graphql.DateTime,
		},
		"finishedAt": &graphql.Field{
			Type: graphql.DateTime,
		},
		"vulnerability": &graphql.Field{
			Type: createVulnerabilityType(),
		},
	}})
}

func createVulnerabilityType() *graphql.Object {
	return graphql.NewObject(graphql.ObjectConfig{Name: "vulnerability", Fields: graphql.Fields{
		"line": &graphql.Field{
			Type: graphql.String,
		},
		"column": &graphql.Field{
			Type: graphql.String,
		},
		"confidence": &graphql.Field{
			Type: graphql.String,
		},
		"file": &graphql.Field{
			Type: graphql.String,
		},
		"code": &graphql.Field{
			Type: graphql.String,
		},
		"details": &graphql.Field{
			Type: graphql.String,
		},
		"type": &graphql.Field{
			Type: graphql.String,
		},
		"vulnerableBelow": &graphql.Field{
			Type: graphql.String,
		},
		"version": &graphql.Field{
			Type: graphql.String,
		},
		"securityTool": &graphql.Field{
			Type: graphql.String,
		},
		"vulnHash": &graphql.Field{
			Type: graphql.String,
		},
		"language": &graphql.Field{
			Type: graphql.String,
		},
		"severity": &graphql.Field{
			Type: graphql.String,
		},
		"commitAuthor": &graphql.Field{
			Type: createCommitAuthor(),
		},
	}})
}

func createCommitAuthor() *graphql.Object {
	return graphql.NewObject(graphql.ObjectConfig{Name: "commitAuthor", Fields: graphql.Fields{
		"author": &graphql.Field{
			Type: graphql.String,
		},
		"email": &graphql.Field{
			Type: graphql.String,
		},
		"commitHash": &graphql.Field{
			Type: graphql.String,
		},
		"message": &graphql.Field{
			Type: graphql.String,
		},
		"date": &graphql.Field{
			Type: graphql.String,
		},
	}})
}
