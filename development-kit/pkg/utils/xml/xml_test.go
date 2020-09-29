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

package xml

import (
	"testing"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/analyser/java"
	"github.com/stretchr/testify/assert"
)

func TestConvertXMLStringtoJSONString(t *testing.T) {
	t.Run("Should return json in format correctly", func(t *testing.T) {
		hw := java.SpotBugsOutput{}
		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Project projectName="">
				<Jar>/tmp/needToBeScanned</Jar>
				<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>
			  </Project>
			</BugCollection>
		`
		err := ConvertXMLToOutput([]byte(output), &hw)
		assert.NoError(t, err)
		assert.NotEmpty(t, hw)
		assert.Equal(t, hw.Project.Jar, "/tmp/needToBeScanned")
	})
}
