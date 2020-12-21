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

package eslint

import (
	"errors"
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"
	"github.com/stretchr/testify/assert"
)

func TestStartAnalysis(t *testing.T) {
	t.Run("should pupulate analysis vulnerabilities", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerMock := &docker.Mock{}
		output := "[{\"filePath\":\"/src/node/auth.js\",\"messages\":[],\"errorCount\":0,\"warningCount\":0,\"fixableErrorCount\":0,\"fixableWarningCount\":0,\"usedDeprecatedRules\":[]},{\"filePath\":\"/src/node/injection.js\",\"messages\":[],\"errorCount\":0,\"warningCount\":0,\"fixableErrorCount\":0,\"fixableWarningCount\":0,\"usedDeprecatedRules\":[]},{\"filePath\":\"/src/node/product.js\",\"messages\":[{\"ruleId\":\"security/detect-unsafe-regex\",\"severity\":1,\"message\":\"Unsafe Regular Expression\",\"line\":53,\"column\":27,\"nodeType\":\"Literal\",\"endLine\":53,\"endColumn\":92}],\"errorCount\":0,\"warningCount\":1,\"fixableErrorCount\":0,\"fixableWarningCount\":0,\"source\":\"var config = require(\\\"../config\\\"),\\n    pgp = require('pg-promise')(),\\n    db = pgp(config.db.connectionString);\\n\\nfunction list_products() {\\n    \\n    var q = \\\"SELECT * FROM products;\\\";\\n\\n    return db.many(q);\\n}\\n\\nfunction getProduct(product_id) {\\n\\n    var q = \\\"SELECT * FROM products WHERE id = '\\\" + product_id + \\\"';\\\";\\n\\n    return db.one(q);\\n}\\n\\nfunction search(query) {\\n\\n    var q = \\\"SELECT * FROM products WHERE name ILIKE '%\\\" + query + \\\"%' OR description ILIKE '%\\\" + query + \\\"%';\\\";\\n\\n    return db.many(q);\\n\\n}\\n\\nfunction purchase(cart) {\\n\\n    var q = \\\"INSERT INTO purchases(mail, product_name, user_name, product_id, address, phone, ship_date, price) VALUES('\\\" +\\n            cart.mail + \\\"', '\\\" +\\n            cart.product_name + \\\"', '\\\" +\\n            cart.username + \\\"', '\\\" +\\n            cart.product_id + \\\"', '\\\" +\\n            cart.address + \\\"', '\\\" +\\n            cart.ship_date + \\\"', '\\\" +\\n            cart.phone + \\\"', '\\\" +\\n            cart.price +\\n            \\\"');\\\";\\n\\n    return db.one(q);\\n\\n}\\n\\nfunction get_purcharsed(username) {\\n\\n    var q = \\\"SELECT * FROM purchases WHERE user_name = '\\\" + username + \\\"';\\\";\\n\\n    return db.many(q);\\n\\n}\\n\\nfunction validateEmail ( string ) {\\n    var emailExpression = /^([a-zA-Z0-9_\\\\.\\\\-])+\\\\@(([a-zA-Z0-9\\\\-])+\\\\.)+([a-zA-Z0-9]{2,4})+$/;\\n\\n    return emailExpression.test( string );\\n}\\n\\nvar actions = {\\n    \\\"list\\\": list_products,\\n    \\\"getProduct\\\": getProduct,\\n    \\\"search\\\": search,\\n    \\\"purchase\\\": purchase,\\n    \\\"getPurchased\\\": get_purcharsed\\n}\\n\\nmodule.exports = actions;\",\"usedDeprecatedRules\":[]}]"
		dockerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		config := &cliConfig.Config{}
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.Equal(t, 1, len(analysis.AnalysisVulnerabilities))
	})

	t.Run("should avoid process when tool is ignored", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerMock := &docker.Mock{}
		output := "[{\"filePath\":\"/src/node/auth.js\",\"messages\":[],\"errorCount\":0,\"warningCount\":0,\"fixableErrorCount\":0,\"fixableWarningCount\":0,\"usedDeprecatedRules\":[]},{\"filePath\":\"/src/node/injection.js\",\"messages\":[],\"errorCount\":0,\"warningCount\":0,\"fixableErrorCount\":0,\"fixableWarningCount\":0,\"usedDeprecatedRules\":[]},{\"filePath\":\"/src/node/product.js\",\"messages\":[{\"ruleId\":\"security/detect-unsafe-regex\",\"severity\":1,\"message\":\"Unsafe Regular Expression\",\"line\":53,\"column\":27,\"nodeType\":\"Literal\",\"endLine\":53,\"endColumn\":92}],\"errorCount\":0,\"warningCount\":1,\"fixableErrorCount\":0,\"fixableWarningCount\":0,\"source\":\"var config = require(\\\"../config\\\"),\\n    pgp = require('pg-promise')(),\\n    db = pgp(config.db.connectionString);\\n\\nfunction list_products() {\\n    \\n    var q = \\\"SELECT * FROM products;\\\";\\n\\n    return db.many(q);\\n}\\n\\nfunction getProduct(product_id) {\\n\\n    var q = \\\"SELECT * FROM products WHERE id = '\\\" + product_id + \\\"';\\\";\\n\\n    return db.one(q);\\n}\\n\\nfunction search(query) {\\n\\n    var q = \\\"SELECT * FROM products WHERE name ILIKE '%\\\" + query + \\\"%' OR description ILIKE '%\\\" + query + \\\"%';\\\";\\n\\n    return db.many(q);\\n\\n}\\n\\nfunction purchase(cart) {\\n\\n    var q = \\\"INSERT INTO purchases(mail, product_name, user_name, product_id, address, phone, ship_date, price) VALUES('\\\" +\\n            cart.mail + \\\"', '\\\" +\\n            cart.product_name + \\\"', '\\\" +\\n            cart.username + \\\"', '\\\" +\\n            cart.product_id + \\\"', '\\\" +\\n            cart.address + \\\"', '\\\" +\\n            cart.ship_date + \\\"', '\\\" +\\n            cart.phone + \\\"', '\\\" +\\n            cart.price +\\n            \\\"');\\\";\\n\\n    return db.one(q);\\n\\n}\\n\\nfunction get_purcharsed(username) {\\n\\n    var q = \\\"SELECT * FROM purchases WHERE user_name = '\\\" + username + \\\"';\\\";\\n\\n    return db.many(q);\\n\\n}\\n\\nfunction validateEmail ( string ) {\\n    var emailExpression = /^([a-zA-Z0-9_\\\\.\\\\-])+\\\\@(([a-zA-Z0-9\\\\-])+\\\\.)+([a-zA-Z0-9]{2,4})+$/;\\n\\n    return emailExpression.test( string );\\n}\\n\\nvar actions = {\\n    \\\"list\\\": list_products,\\n    \\\"getProduct\\\": getProduct,\\n    \\\"search\\\": search,\\n    \\\"purchase\\\": purchase,\\n    \\\"getPurchased\\\": get_purcharsed\\n}\\n\\nmodule.exports = actions;\",\"usedDeprecatedRules\":[]}]"
		dockerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		config := &cliConfig.Config{}
		config.SetToolsToIgnore([]string{"Eslint"})
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities))
	})

	t.Run("should avoid process when tool return an empty string", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerMock := &docker.Mock{}
		output := ""
		dockerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		config := &cliConfig.Config{}
		config.SetToolsToIgnore([]string{"Eslint"})
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities))
	})

	t.Run("should avoid process when docker fails", func(t *testing.T) {
		analysis := &horusec.Analysis{}
		dockerMock := &docker.Mock{}
		dockerMock.On("CreateLanguageAnalysisContainer").Return(nil, errors.New("test"))

		config := &cliConfig.Config{}
		config.SetToolsToIgnore([]string{"Eslint"})
		config.SetWorkDir(&workdir.WorkDir{})

		service := formatters.NewFormatterService(analysis, dockerMock, config, &horusec.Monitor{})
		formatter := NewFormatter(service)

		formatter.StartAnalysis("")

		assert.Equal(t, 0, len(analysis.AnalysisVulnerabilities))
	})
}
