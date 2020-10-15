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

package spotbugs

import (
	"errors"
	"testing"
	"time"

	cliConfig "github.com/ZupIT/horusec/horusec-cli/config"
	"github.com/ZupIT/horusec/horusec-cli/internal/entities/workdir"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/docker"
	"github.com/ZupIT/horusec/horusec-cli/internal/services/formatters"

	"github.com/ZupIT/horusec/development-kit/pkg/entities/horusec"
	enumsHorusec "github.com/ZupIT/horusec/development-kit/pkg/enums/horusec"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func AnalysisMock() *horusec.Analysis {
	return &horusec.Analysis{
		ID:           uuid.New(),
		CreatedAt:    time.Now(),
		RepositoryID: uuid.New(),
		Status:       enumsHorusec.Running,
	}
}

func TestJava_StartAnalysis(t *testing.T) {
	t.Run("Should run analysis without panics", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Project projectName="">
				<Jar>/tmp/needToBeScanned</Jar>
				<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>
			  </Project>
			  <BugInstance type="PREDICTABLE_RANDOM" priority="2" rank="12" abbrev="SECPR" category="SECURITY">
				<Class classname="com.mycompany.app.App">
				  <SourceLine classname="com.mycompany.app.App" start="8" end="15" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Class>
				<Method classname="com.mycompany.app.App" name="main" signature="([Ljava/lang/String;)V" isStatic="true">
				  <SourceLine classname="com.mycompany.app.App" start="12" end="15" startBytecode="0" endBytecode="92" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Method>
				<SourceLine classname="com.mycompany.app.App" start="12" end="12" startBytecode="4" endBytecode="4" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				<String value="java.util.Random"/>
			  </BugInstance>
			  <Errors errors="0" missingClasses="0"></Errors>
			  <FindBugsSummary timestamp="Tue, 2 Jun 2020 18:14:46 +0000" total_classes="1" referenced_classes="13" total_bugs="1" total_size="8" num_packages="1" java_version="1.8.0_212" vm_version="25.222-b10" cpu_seconds="4.22" clock_seconds="0.94" peak_mbytes="123.32" alloc_mbytes="3531.00" gc_seconds="0.06" priority_2="1">
				<PackageStats package="com.mycompany.app" total_bugs="1" total_types="1" total_size="8" priority_2="1">
				  <ClassStats class="com.mycompany.app.App" sourceFile="App.java" interface="false" size="8" bugs="1" priority_2="1"/>
				</PackageStats>
				<FindBugsProfile>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassInfoAnalysisEngine" totalMilliseconds="156" invocations="348" avgMicrosecondsPerInvocation="449" maxMicrosecondsPerInvocation="13080" standardDeviationMicrosecondsPerInvocation="1141"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FunctionsThatMightBeMistakenForProcedures" totalMilliseconds="62" invocations="13" avgMicrosecondsPerInvocation="4779" maxMicrosecondsPerInvocation="50604" standardDeviationMicrosecondsPerInvocation="13300"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FieldItemSummary" totalMilliseconds="43" invocations="13" avgMicrosecondsPerInvocation="3342" maxMicrosecondsPerInvocation="12427" standardDeviationMicrosecondsPerInvocation="3595"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassDataAnalysisEngine" totalMilliseconds="39" invocations="349" avgMicrosecondsPerInvocation="114" maxMicrosecondsPerInvocation="465" standardDeviationMicrosecondsPerInvocation="69"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FindNoSideEffectMethods" totalMilliseconds="32" invocations="13" avgMicrosecondsPerInvocation="2485" maxMicrosecondsPerInvocation="8004" standardDeviationMicrosecondsPerInvocation="2629"/>
				  <ClassProfile name="edu.umd.cs.findbugs.OpcodeStack$JumpInfoFactory" totalMilliseconds="28" invocations="67" avgMicrosecondsPerInvocation="425" maxMicrosecondsPerInvocation="2975" standardDeviationMicrosecondsPerInvocation="510"/>
				  <ClassProfile name="edu.umd.cs.findbugs.util.TopologicalSort" totalMilliseconds="27" invocations="316" avgMicrosecondsPerInvocation="86" maxMicrosecondsPerInvocation="1731" standardDeviationMicrosecondsPerInvocation="165"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.MethodGenFactory" totalMilliseconds="25" invocations="2" avgMicrosecondsPerInvocation="12575" maxMicrosecondsPerInvocation="24673" standardDeviationMicrosecondsPerInvocation="12098"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.JavaClassAnalysisEngine" totalMilliseconds="19" invocations="38" avgMicrosecondsPerInvocation="503" maxMicrosecondsPerInvocation="8823" standardDeviationMicrosecondsPerInvocation="1463"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.NoteDirectlyRelevantTypeQualifiers" totalMilliseconds="18" invocations="13" avgMicrosecondsPerInvocation="1430" maxMicrosecondsPerInvocation="8671" standardDeviationMicrosecondsPerInvocation="2206"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.OverridingEqualsNotSymmetrical" totalMilliseconds="13" invocations="13" avgMicrosecondsPerInvocation="1065" maxMicrosecondsPerInvocation="7871" standardDeviationMicrosecondsPerInvocation="2044"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.BuildStringPassthruGraph" totalMilliseconds="11" invocations="13" avgMicrosecondsPerInvocation="921" maxMicrosecondsPerInvocation="6009" standardDeviationMicrosecondsPerInvocation="1543"/>
				</FindBugsProfile>
			  </FindBugsSummary>
			  <ClassFeatures></ClassFeatures>
			  <History></History>
			</BugCollection>
		`
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
			assert.Empty(t, analysis.Errors)
			assert.Len(t, analysis.AnalysisVulnerabilities, 1)
		})
	})

	t.Run("Should not run analysis if java is finished docker_api", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return error when up spotbugs in docker_api", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", errors.New("clone error"))

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return error when output is wrong spotbugs in docker_api", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := "this text is wrong for java output"

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return not error when output is empty spotbugs in docker_api", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("", nil)

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return not error when output return numErrors is type wrong", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Errors errors="a" missingClasses="0"></Errors>
			</BugCollection>
		`
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return not error when output return missingClasses is type wrong", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Errors errors="0" missingClasses="b"></Errors>
			</BugCollection>
		`
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return not error when SpotBugsIssue len equals zero and exists errors", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Errors errors="1" missingClasses="1"></Errors>
			</BugCollection>
		`
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return analysis with confidence high", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Project projectName="">
				<Jar>/tmp/needToBeScanned</Jar>
				<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>
			  </Project>
			  <BugInstance type="PREDICTABLE_RANDOM" priority="1" rank="12" abbrev="SECPR" category="SECURITY">
				<Class classname="com.mycompany.app.App">
				  <SourceLine classname="com.mycompany.app.App" start="8" end="15" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Class>
				<Method classname="com.mycompany.app.App" name="main" signature="([Ljava/lang/String;)V" isStatic="true">
				  <SourceLine classname="com.mycompany.app.App" start="12" end="15" startBytecode="0" endBytecode="92" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Method>
				<SourceLine classname="com.mycompany.app.App" start="12" end="12" startBytecode="4" endBytecode="4" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				<String value="java.util.Random"/>
			  </BugInstance>
			  <Errors errors="0" missingClasses="0"></Errors>
			  <FindBugsSummary timestamp="Tue, 2 Jun 2020 18:14:46 +0000" total_classes="1" referenced_classes="13" total_bugs="1" total_size="8" num_packages="1" java_version="1.8.0_212" vm_version="25.222-b10" cpu_seconds="4.22" clock_seconds="0.94" peak_mbytes="123.32" alloc_mbytes="3531.00" gc_seconds="0.06" priority_2="1">
				<PackageStats package="com.mycompany.app" total_bugs="1" total_types="1" total_size="8" priority_2="1">
				  <ClassStats class="com.mycompany.app.App" sourceFile="App.java" interface="false" size="8" bugs="1" priority_2="1"/>
				</PackageStats>
				<FindBugsProfile>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassInfoAnalysisEngine" totalMilliseconds="156" invocations="348" avgMicrosecondsPerInvocation="449" maxMicrosecondsPerInvocation="13080" standardDeviationMicrosecondsPerInvocation="1141"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FunctionsThatMightBeMistakenForProcedures" totalMilliseconds="62" invocations="13" avgMicrosecondsPerInvocation="4779" maxMicrosecondsPerInvocation="50604" standardDeviationMicrosecondsPerInvocation="13300"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FieldItemSummary" totalMilliseconds="43" invocations="13" avgMicrosecondsPerInvocation="3342" maxMicrosecondsPerInvocation="12427" standardDeviationMicrosecondsPerInvocation="3595"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassDataAnalysisEngine" totalMilliseconds="39" invocations="349" avgMicrosecondsPerInvocation="114" maxMicrosecondsPerInvocation="465" standardDeviationMicrosecondsPerInvocation="69"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FindNoSideEffectMethods" totalMilliseconds="32" invocations="13" avgMicrosecondsPerInvocation="2485" maxMicrosecondsPerInvocation="8004" standardDeviationMicrosecondsPerInvocation="2629"/>
				  <ClassProfile name="edu.umd.cs.findbugs.OpcodeStack$JumpInfoFactory" totalMilliseconds="28" invocations="67" avgMicrosecondsPerInvocation="425" maxMicrosecondsPerInvocation="2975" standardDeviationMicrosecondsPerInvocation="510"/>
				  <ClassProfile name="edu.umd.cs.findbugs.util.TopologicalSort" totalMilliseconds="27" invocations="316" avgMicrosecondsPerInvocation="86" maxMicrosecondsPerInvocation="1731" standardDeviationMicrosecondsPerInvocation="165"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.MethodGenFactory" totalMilliseconds="25" invocations="2" avgMicrosecondsPerInvocation="12575" maxMicrosecondsPerInvocation="24673" standardDeviationMicrosecondsPerInvocation="12098"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.JavaClassAnalysisEngine" totalMilliseconds="19" invocations="38" avgMicrosecondsPerInvocation="503" maxMicrosecondsPerInvocation="8823" standardDeviationMicrosecondsPerInvocation="1463"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.NoteDirectlyRelevantTypeQualifiers" totalMilliseconds="18" invocations="13" avgMicrosecondsPerInvocation="1430" maxMicrosecondsPerInvocation="8671" standardDeviationMicrosecondsPerInvocation="2206"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.OverridingEqualsNotSymmetrical" totalMilliseconds="13" invocations="13" avgMicrosecondsPerInvocation="1065" maxMicrosecondsPerInvocation="7871" standardDeviationMicrosecondsPerInvocation="2044"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.BuildStringPassthruGraph" totalMilliseconds="11" invocations="13" avgMicrosecondsPerInvocation="921" maxMicrosecondsPerInvocation="6009" standardDeviationMicrosecondsPerInvocation="1543"/>
				</FindBugsProfile>
			  </FindBugsSummary>
			  <ClassFeatures></ClassFeatures>
			  <History></History>
			</BugCollection>
		`

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return analysis with confidence LOW", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Project projectName="">
				<Jar>/tmp/needToBeScanned</Jar>
				<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>
			  </Project>
			  <BugInstance type="PREDICTABLE_RANDOM" priority="3" rank="12" abbrev="SECPR" category="SECURITY">
				<Class classname="com.mycompany.app.App">
				  <SourceLine classname="com.mycompany.app.App" start="8" end="15" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Class>
				<Method classname="com.mycompany.app.App" name="main" signature="([Ljava/lang/String;)V" isStatic="true">
				  <SourceLine classname="com.mycompany.app.App" start="12" end="15" startBytecode="0" endBytecode="92" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Method>
				<SourceLine classname="com.mycompany.app.App" start="12" end="12" startBytecode="4" endBytecode="4" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				<String value="java.util.Random"/>
			  </BugInstance>
			  <Errors errors="0" missingClasses="0"></Errors>
			  <FindBugsSummary timestamp="Tue, 2 Jun 2020 18:14:46 +0000" total_classes="1" referenced_classes="13" total_bugs="1" total_size="8" num_packages="1" java_version="1.8.0_212" vm_version="25.222-b10" cpu_seconds="4.22" clock_seconds="0.94" peak_mbytes="123.32" alloc_mbytes="3531.00" gc_seconds="0.06" priority_2="1">
				<PackageStats package="com.mycompany.app" total_bugs="1" total_types="1" total_size="8" priority_2="1">
				  <ClassStats class="com.mycompany.app.App" sourceFile="App.java" interface="false" size="8" bugs="1" priority_2="1"/>
				</PackageStats>
				<FindBugsProfile>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassInfoAnalysisEngine" totalMilliseconds="156" invocations="348" avgMicrosecondsPerInvocation="449" maxMicrosecondsPerInvocation="13080" standardDeviationMicrosecondsPerInvocation="1141"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FunctionsThatMightBeMistakenForProcedures" totalMilliseconds="62" invocations="13" avgMicrosecondsPerInvocation="4779" maxMicrosecondsPerInvocation="50604" standardDeviationMicrosecondsPerInvocation="13300"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FieldItemSummary" totalMilliseconds="43" invocations="13" avgMicrosecondsPerInvocation="3342" maxMicrosecondsPerInvocation="12427" standardDeviationMicrosecondsPerInvocation="3595"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassDataAnalysisEngine" totalMilliseconds="39" invocations="349" avgMicrosecondsPerInvocation="114" maxMicrosecondsPerInvocation="465" standardDeviationMicrosecondsPerInvocation="69"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FindNoSideEffectMethods" totalMilliseconds="32" invocations="13" avgMicrosecondsPerInvocation="2485" maxMicrosecondsPerInvocation="8004" standardDeviationMicrosecondsPerInvocation="2629"/>
				  <ClassProfile name="edu.umd.cs.findbugs.OpcodeStack$JumpInfoFactory" totalMilliseconds="28" invocations="67" avgMicrosecondsPerInvocation="425" maxMicrosecondsPerInvocation="2975" standardDeviationMicrosecondsPerInvocation="510"/>
				  <ClassProfile name="edu.umd.cs.findbugs.util.TopologicalSort" totalMilliseconds="27" invocations="316" avgMicrosecondsPerInvocation="86" maxMicrosecondsPerInvocation="1731" standardDeviationMicrosecondsPerInvocation="165"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.MethodGenFactory" totalMilliseconds="25" invocations="2" avgMicrosecondsPerInvocation="12575" maxMicrosecondsPerInvocation="24673" standardDeviationMicrosecondsPerInvocation="12098"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.JavaClassAnalysisEngine" totalMilliseconds="19" invocations="38" avgMicrosecondsPerInvocation="503" maxMicrosecondsPerInvocation="8823" standardDeviationMicrosecondsPerInvocation="1463"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.NoteDirectlyRelevantTypeQualifiers" totalMilliseconds="18" invocations="13" avgMicrosecondsPerInvocation="1430" maxMicrosecondsPerInvocation="8671" standardDeviationMicrosecondsPerInvocation="2206"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.OverridingEqualsNotSymmetrical" totalMilliseconds="13" invocations="13" avgMicrosecondsPerInvocation="1065" maxMicrosecondsPerInvocation="7871" standardDeviationMicrosecondsPerInvocation="2044"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.BuildStringPassthruGraph" totalMilliseconds="11" invocations="13" avgMicrosecondsPerInvocation="921" maxMicrosecondsPerInvocation="6009" standardDeviationMicrosecondsPerInvocation="1543"/>
				</FindBugsProfile>
			  </FindBugsSummary>
			  <ClassFeatures></ClassFeatures>
			  <History></History>
			</BugCollection>
		`
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return analysis with severity high", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Project projectName="">
				<Jar>/tmp/needToBeScanned</Jar>
				<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>
			  </Project>
			  <BugInstance type="PREDICTABLE_RANDOM" priority="2" rank="1" abbrev="SECPR" category="SECURITY">
				<Class classname="com.mycompany.app.App">
				  <SourceLine classname="com.mycompany.app.App" start="8" end="15" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Class>
				<Method classname="com.mycompany.app.App" name="main" signature="([Ljava/lang/String;)V" isStatic="true">
				  <SourceLine classname="com.mycompany.app.App" start="12" end="15" startBytecode="0" endBytecode="92" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Method>
				<SourceLine classname="com.mycompany.app.App" start="12" end="12" startBytecode="4" endBytecode="4" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				<String value="java.util.Random"/>
			  </BugInstance>
			  <Errors errors="0" missingClasses="0"></Errors>
			  <FindBugsSummary timestamp="Tue, 2 Jun 2020 18:14:46 +0000" total_classes="1" referenced_classes="13" total_bugs="1" total_size="8" num_packages="1" java_version="1.8.0_212" vm_version="25.222-b10" cpu_seconds="4.22" clock_seconds="0.94" peak_mbytes="123.32" alloc_mbytes="3531.00" gc_seconds="0.06" priority_2="1">
				<PackageStats package="com.mycompany.app" total_bugs="1" total_types="1" total_size="8" priority_2="1">
				  <ClassStats class="com.mycompany.app.App" sourceFile="App.java" interface="false" size="8" bugs="1" priority_2="1"/>
				</PackageStats>
				<FindBugsProfile>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassInfoAnalysisEngine" totalMilliseconds="156" invocations="348" avgMicrosecondsPerInvocation="449" maxMicrosecondsPerInvocation="13080" standardDeviationMicrosecondsPerInvocation="1141"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FunctionsThatMightBeMistakenForProcedures" totalMilliseconds="62" invocations="13" avgMicrosecondsPerInvocation="4779" maxMicrosecondsPerInvocation="50604" standardDeviationMicrosecondsPerInvocation="13300"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FieldItemSummary" totalMilliseconds="43" invocations="13" avgMicrosecondsPerInvocation="3342" maxMicrosecondsPerInvocation="12427" standardDeviationMicrosecondsPerInvocation="3595"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassDataAnalysisEngine" totalMilliseconds="39" invocations="349" avgMicrosecondsPerInvocation="114" maxMicrosecondsPerInvocation="465" standardDeviationMicrosecondsPerInvocation="69"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FindNoSideEffectMethods" totalMilliseconds="32" invocations="13" avgMicrosecondsPerInvocation="2485" maxMicrosecondsPerInvocation="8004" standardDeviationMicrosecondsPerInvocation="2629"/>
				  <ClassProfile name="edu.umd.cs.findbugs.OpcodeStack$JumpInfoFactory" totalMilliseconds="28" invocations="67" avgMicrosecondsPerInvocation="425" maxMicrosecondsPerInvocation="2975" standardDeviationMicrosecondsPerInvocation="510"/>
				  <ClassProfile name="edu.umd.cs.findbugs.util.TopologicalSort" totalMilliseconds="27" invocations="316" avgMicrosecondsPerInvocation="86" maxMicrosecondsPerInvocation="1731" standardDeviationMicrosecondsPerInvocation="165"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.MethodGenFactory" totalMilliseconds="25" invocations="2" avgMicrosecondsPerInvocation="12575" maxMicrosecondsPerInvocation="24673" standardDeviationMicrosecondsPerInvocation="12098"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.JavaClassAnalysisEngine" totalMilliseconds="19" invocations="38" avgMicrosecondsPerInvocation="503" maxMicrosecondsPerInvocation="8823" standardDeviationMicrosecondsPerInvocation="1463"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.NoteDirectlyRelevantTypeQualifiers" totalMilliseconds="18" invocations="13" avgMicrosecondsPerInvocation="1430" maxMicrosecondsPerInvocation="8671" standardDeviationMicrosecondsPerInvocation="2206"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.OverridingEqualsNotSymmetrical" totalMilliseconds="13" invocations="13" avgMicrosecondsPerInvocation="1065" maxMicrosecondsPerInvocation="7871" standardDeviationMicrosecondsPerInvocation="2044"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.BuildStringPassthruGraph" totalMilliseconds="11" invocations="13" avgMicrosecondsPerInvocation="921" maxMicrosecondsPerInvocation="6009" standardDeviationMicrosecondsPerInvocation="1543"/>
				</FindBugsProfile>
			  </FindBugsSummary>
			  <ClassFeatures></ClassFeatures>
			  <History></History>
			</BugCollection>
		`
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return analysis with severity low", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591121686000" analysisTimestamp="1591121687367" release="">
			  <Project projectName="">
				<Jar>/tmp/needToBeScanned</Jar>
				<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>
			  </Project>
			  <BugInstance type="PREDICTABLE_RANDOM" priority="2" rank="15" abbrev="SECPR" category="SECURITY">
				<Class classname="com.mycompany.app.App">
				  <SourceLine classname="com.mycompany.app.App" start="8" end="15" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Class>
				<Method classname="com.mycompany.app.App" name="main" signature="([Ljava/lang/String;)V" isStatic="true">
				  <SourceLine classname="com.mycompany.app.App" start="12" end="15" startBytecode="0" endBytecode="92" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				</Method>
				<SourceLine classname="com.mycompany.app.App" start="12" end="12" startBytecode="4" endBytecode="4" sourcefile="App.java" sourcepath="com/mycompany/app/App.java"/>
				<String value="java.util.Random"/>
			  </BugInstance>
			  <Errors errors="0" missingClasses="0"></Errors>
			  <FindBugsSummary timestamp="Tue, 2 Jun 2020 18:14:46 +0000" total_classes="1" referenced_classes="13" total_bugs="1" total_size="8" num_packages="1" java_version="1.8.0_212" vm_version="25.222-b10" cpu_seconds="4.22" clock_seconds="0.94" peak_mbytes="123.32" alloc_mbytes="3531.00" gc_seconds="0.06" priority_2="1">
				<PackageStats package="com.mycompany.app" total_bugs="1" total_types="1" total_size="8" priority_2="1">
				  <ClassStats class="com.mycompany.app.App" sourceFile="App.java" interface="false" size="8" bugs="1" priority_2="1"/>
				</PackageStats>
				<FindBugsProfile>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassInfoAnalysisEngine" totalMilliseconds="156" invocations="348" avgMicrosecondsPerInvocation="449" maxMicrosecondsPerInvocation="13080" standardDeviationMicrosecondsPerInvocation="1141"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FunctionsThatMightBeMistakenForProcedures" totalMilliseconds="62" invocations="13" avgMicrosecondsPerInvocation="4779" maxMicrosecondsPerInvocation="50604" standardDeviationMicrosecondsPerInvocation="13300"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FieldItemSummary" totalMilliseconds="43" invocations="13" avgMicrosecondsPerInvocation="3342" maxMicrosecondsPerInvocation="12427" standardDeviationMicrosecondsPerInvocation="3595"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassDataAnalysisEngine" totalMilliseconds="39" invocations="349" avgMicrosecondsPerInvocation="114" maxMicrosecondsPerInvocation="465" standardDeviationMicrosecondsPerInvocation="69"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FindNoSideEffectMethods" totalMilliseconds="32" invocations="13" avgMicrosecondsPerInvocation="2485" maxMicrosecondsPerInvocation="8004" standardDeviationMicrosecondsPerInvocation="2629"/>
				  <ClassProfile name="edu.umd.cs.findbugs.OpcodeStack$JumpInfoFactory" totalMilliseconds="28" invocations="67" avgMicrosecondsPerInvocation="425" maxMicrosecondsPerInvocation="2975" standardDeviationMicrosecondsPerInvocation="510"/>
				  <ClassProfile name="edu.umd.cs.findbugs.util.TopologicalSort" totalMilliseconds="27" invocations="316" avgMicrosecondsPerInvocation="86" maxMicrosecondsPerInvocation="1731" standardDeviationMicrosecondsPerInvocation="165"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.MethodGenFactory" totalMilliseconds="25" invocations="2" avgMicrosecondsPerInvocation="12575" maxMicrosecondsPerInvocation="24673" standardDeviationMicrosecondsPerInvocation="12098"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.JavaClassAnalysisEngine" totalMilliseconds="19" invocations="38" avgMicrosecondsPerInvocation="503" maxMicrosecondsPerInvocation="8823" standardDeviationMicrosecondsPerInvocation="1463"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.NoteDirectlyRelevantTypeQualifiers" totalMilliseconds="18" invocations="13" avgMicrosecondsPerInvocation="1430" maxMicrosecondsPerInvocation="8671" standardDeviationMicrosecondsPerInvocation="2206"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.OverridingEqualsNotSymmetrical" totalMilliseconds="13" invocations="13" avgMicrosecondsPerInvocation="1065" maxMicrosecondsPerInvocation="7871" standardDeviationMicrosecondsPerInvocation="2044"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.BuildStringPassthruGraph" totalMilliseconds="11" invocations="13" avgMicrosecondsPerInvocation="921" maxMicrosecondsPerInvocation="6009" standardDeviationMicrosecondsPerInvocation="1543"/>
				</FindBugsProfile>
			  </FindBugsSummary>
			  <ClassFeatures></ClassFeatures>
			  <History></History>
			</BugCollection>
		`
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})

	t.Run("Should return analysis with 10 medium severity kotlin", func(t *testing.T) {
		dockerAPIControllerMock := &docker.Mock{}
		dockerAPIControllerMock.On("SetAnalysisID")

		config := &cliConfig.Config{
			WorkDir: &workdir.WorkDir{},
		}

		output := `<?xml version="1.0" encoding="UTF-8"?>
			<BugCollection version="4.0.0-beta4" sequence="0" timestamp="1591213178000" analysisTimestamp="1591213179658" release="">
			  <Project projectName="">
				<Jar>/tmp/needToBeScanned</Jar>
				<Plugin id="com.h3xstream.findsecbugs" enabled="true"/>
			  </Project>
			  <BugInstance type="HARD_CODE_PASSWORD" priority="2" rank="12" abbrev="SECHCP" category="SECURITY">
				<Class classname="hello.EqualsPasswordField">
				  <SourceLine classname="hello.EqualsPasswordField" start="3" end="66" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Class>
				<Method classname="hello.EqualsPasswordField" name="hardcodedLogin1" signature="(Ljava/lang/String;Ljava/lang/String;)Z" isStatic="false">
				  <SourceLine classname="hello.EqualsPasswordField" start="7" end="18" startBytecode="0" endBytecode="170" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Method>
				<SourceLine classname="hello.EqualsPasswordField" start="14" end="14" startBytecode="59" endBytecode="59" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				<String value="kotlin/jvm/internal/Intrinsics.areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z" role="Sink method"/>
				<String value="0" role="Sink parameter"/>
			  </BugInstance>
			  <BugInstance type="HARD_CODE_PASSWORD" priority="2" rank="12" abbrev="SECHCP" category="SECURITY">
				<Class classname="hello.EqualsPasswordField">
				  <SourceLine classname="hello.EqualsPasswordField" start="3" end="66" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Class>
				<Method classname="hello.EqualsPasswordField" name="hardcodedLogin2" signature="(Ljava/lang/String;Ljava/lang/String;)Z" isStatic="false">
				  <SourceLine classname="hello.EqualsPasswordField" start="23" end="23" startBytecode="0" endBytecode="116" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Method>
				<SourceLine classname="hello.EqualsPasswordField" start="23" end="23" startBytecode="15" endBytecode="15" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				<String value="kotlin/jvm/internal/Intrinsics.areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z" role="Sink method"/>
				<String value="0" role="Sink parameter"/>
				<String value="not detected" role="Method usage"/>
				<SourceLine classname="hello.EqualsPasswordField" startBytecode="9" endBytecode="9" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
			  </BugInstance>
			  <BugInstance type="HARD_CODE_PASSWORD" priority="2" rank="9" abbrev="SECHCP" category="SECURITY">
				<Class classname="hello.EqualsPasswordField">
				  <SourceLine classname="hello.EqualsPasswordField" start="3" end="66" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Class>
				<Method classname="hello.EqualsPasswordField" name="hardcodedLogin3" signature="(Ljava/lang/String;Ljava/lang/String;)Z" isStatic="false">
				  <SourceLine classname="hello.EqualsPasswordField" start="31" end="32" startBytecode="0" endBytecode="137" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Method>
				<SourceLine classname="hello.EqualsPasswordField" start="32" end="32" startBytecode="17" endBytecode="17" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				<String value="kotlin/jvm/internal/Intrinsics.areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z" role="Sink method"/>
				<String value="0" role="Sink parameter"/>
				<String value="not detected" role="Method usage"/>
				<SourceLine classname="hello.EqualsPasswordField" startBytecode="9" endBytecode="9" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
			  </BugInstance>
			  <BugInstance type="HARD_CODE_PASSWORD" priority="2" rank="999" abbrev="SECHCP" category="SECURITY">
				<Class classname="hello.HelloKt">
				  <SourceLine classname="hello.HelloKt" start="76" end="151" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Class>
				<Method classname="hello.HelloKt" name="hardcodedLogin1" signature="(Ljava/lang/String;Ljava/lang/String;)Z" isStatic="true">
				  <SourceLine classname="hello.HelloKt" start="76" end="87" startBytecode="0" endBytecode="157" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Method>
				<SourceLine classname="hello.HelloKt" start="83" end="83" startBytecode="57" endBytecode="57" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				<String value="kotlin/jvm/internal/Intrinsics.areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z" role="Sink method"/>
				<String value="0" role="Sink parameter"/>
			  </BugInstance>
			  <BugInstance type="HARD_CODE_PASSWORD" priority="2" rank="12" abbrev="SECHCP" category="SECURITY">
				<Class classname="hello.HelloKt">
				  <SourceLine classname="hello.HelloKt" start="76" end="151" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Class>
				<Method classname="hello.HelloKt" name="hardcodedLogin2" signature="(Ljava/lang/String;Ljava/lang/String;)Z" isStatic="true">
				  <SourceLine classname="hello.HelloKt" start="92" end="92" startBytecode="0" endBytecode="105" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Method>
				<SourceLine classname="hello.HelloKt" start="92" end="92" startBytecode="15" endBytecode="15" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				<String value="kotlin/jvm/internal/Intrinsics.areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z" role="Sink method"/>
				<String value="0" role="Sink parameter"/>
				<String value="not detected" role="Method usage"/>
				<SourceLine classname="hello.HelloKt" startBytecode="9" endBytecode="9" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
			  </BugInstance>
			  <BugInstance type="HARD_CODE_PASSWORD" priority="2" rank="12" abbrev="SECHCP" category="SECURITY">
				<Class classname="hello.HelloKt">
				  <SourceLine classname="hello.HelloKt" start="76" end="151" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Class>
				<Method classname="hello.HelloKt" name="hardcodedLogin3" signature="(Ljava/lang/String;Ljava/lang/String;)Z" isStatic="true">
				  <SourceLine classname="hello.HelloKt" start="100" end="101" startBytecode="0" endBytecode="126" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				</Method>
				<SourceLine classname="hello.HelloKt" start="101" end="101" startBytecode="17" endBytecode="17" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
				<String value="kotlin/jvm/internal/Intrinsics.areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z" role="Sink method"/>
				<String value="0" role="Sink parameter"/>
				<String value="not detected" role="Method usage"/>
				<SourceLine classname="hello.HelloKt" startBytecode="9" endBytecode="9" sourcefile="Hello.kt" sourcepath="hello/Hello.kt"/>
			  </BugInstance>
			  <Errors errors="0" missingClasses="1">
				<MissingClass>kotlin.jvm.internal.Intrinsics</MissingClass>
			  </Errors>
			  <FindBugsSummary timestamp="Wed, 3 Jun 2020 19:39:38 +0000" total_classes="2" referenced_classes="14" total_bugs="6" total_size="80" num_packages="1" java_version="1.8.0_212" vm_version="25.222-b10" cpu_seconds="5.77" clock_seconds="1.24" peak_mbytes="151.16" alloc_mbytes="3531.00" gc_seconds="0.06" priority_2="6">
				<PackageStats package="hello" total_bugs="6" total_types="2" total_size="80" priority_2="6">
				  <ClassStats class="hello.EqualsPasswordField" sourceFile="Hello.kt" interface="false" size="38" bugs="3" priority_2="3"/>
				  <ClassStats class="hello.HelloKt" sourceFile="Hello.kt" interface="false" size="42" bugs="3" priority_2="3"/>
				</PackageStats>
				<FindBugsProfile>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassInfoAnalysisEngine" totalMilliseconds="169" invocations="337" avgMicrosecondsPerInvocation="503" maxMicrosecondsPerInvocation="14175" standardDeviationMicrosecondsPerInvocation="1246"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.NoteDirectlyRelevantTypeQualifiers" totalMilliseconds="75" invocations="14" avgMicrosecondsPerInvocation="5412" maxMicrosecondsPerInvocation="63815" standardDeviationMicrosecondsPerInvocation="16222"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FieldItemSummary" totalMilliseconds="47" invocations="14" avgMicrosecondsPerInvocation="3378" maxMicrosecondsPerInvocation="13669" standardDeviationMicrosecondsPerInvocation="4119"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.ClassDataAnalysisEngine" totalMilliseconds="43" invocations="338" avgMicrosecondsPerInvocation="127" maxMicrosecondsPerInvocation="525" standardDeviationMicrosecondsPerInvocation="76"/>
				  <ClassProfile name="edu.umd.cs.findbugs.OpcodeStack$JumpInfoFactory" totalMilliseconds="36" invocations="76" avgMicrosecondsPerInvocation="483" maxMicrosecondsPerInvocation="2934" standardDeviationMicrosecondsPerInvocation="544"/>
				  <ClassProfile name="edu.umd.cs.findbugs.util.TopologicalSort" totalMilliseconds="30" invocations="302" avgMicrosecondsPerInvocation="102" maxMicrosecondsPerInvocation="1483" standardDeviationMicrosecondsPerInvocation="180"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.MethodGenFactory" totalMilliseconds="30" invocations="20" avgMicrosecondsPerInvocation="1539" maxMicrosecondsPerInvocation="28040" standardDeviationMicrosecondsPerInvocation="6080"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FindNoSideEffectMethods" totalMilliseconds="28" invocations="14" avgMicrosecondsPerInvocation="2071" maxMicrosecondsPerInvocation="7498" standardDeviationMicrosecondsPerInvocation="2147"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.JavaClassAnalysisEngine" totalMilliseconds="24" invocations="38" avgMicrosecondsPerInvocation="647" maxMicrosecondsPerInvocation="10379" standardDeviationMicrosecondsPerInvocation="1725"/>
				  <ClassProfile name="com.h3xstream.findsecbugs.taintanalysis.TaintDataflowEngine" totalMilliseconds="22" invocations="18" avgMicrosecondsPerInvocation="1274" maxMicrosecondsPerInvocation="7861" standardDeviationMicrosecondsPerInvocation="1642"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.TypeDataflowFactory" totalMilliseconds="21" invocations="20" avgMicrosecondsPerInvocation="1068" maxMicrosecondsPerInvocation="13370" standardDeviationMicrosecondsPerInvocation="2827"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.IsNullValueDataflowFactory" totalMilliseconds="19" invocations="18" avgMicrosecondsPerInvocation="1110" maxMicrosecondsPerInvocation="7362" standardDeviationMicrosecondsPerInvocation="1577"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.ValueNumberDataflowFactory" totalMilliseconds="19" invocations="20" avgMicrosecondsPerInvocation="984" maxMicrosecondsPerInvocation="12927" standardDeviationMicrosecondsPerInvocation="2745"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.CFGFactory" totalMilliseconds="18" invocations="20" avgMicrosecondsPerInvocation="926" maxMicrosecondsPerInvocation="11424" standardDeviationMicrosecondsPerInvocation="2413"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.FunctionsThatMightBeMistakenForProcedures" totalMilliseconds="17" invocations="14" avgMicrosecondsPerInvocation="1232" maxMicrosecondsPerInvocation="7195" standardDeviationMicrosecondsPerInvocation="1990"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.BuildStringPassthruGraph" totalMilliseconds="14" invocations="14" avgMicrosecondsPerInvocation="1053" maxMicrosecondsPerInvocation="5577" standardDeviationMicrosecondsPerInvocation="1427"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.OverridingEqualsNotSymmetrical" totalMilliseconds="14" invocations="14" avgMicrosecondsPerInvocation="1026" maxMicrosecondsPerInvocation="7355" standardDeviationMicrosecondsPerInvocation="1881"/>
				  <ClassProfile name="edu.umd.cs.findbugs.detect.BuildObligationPolicyDatabase" totalMilliseconds="13" invocations="14" avgMicrosecondsPerInvocation="966" maxMicrosecondsPerInvocation="2946" standardDeviationMicrosecondsPerInvocation="948"/>
				  <ClassProfile name="edu.umd.cs.findbugs.classfile.engine.bcel.UnconditionalValueDerefDataflowFactory" totalMilliseconds="12" invocations="18" avgMicrosecondsPerInvocation="701" maxMicrosecondsPerInvocation="1960" standardDeviationMicrosecondsPerInvocation="444"/>
				  <ClassProfile name="edu.umd.cs.findbugs.ba.npe.NullDerefAndRedundantComparisonFinder" totalMilliseconds="11" invocations="18" avgMicrosecondsPerInvocation="612" maxMicrosecondsPerInvocation="1446" standardDeviationMicrosecondsPerInvocation="306"/>
				</FindBugsProfile>
			  </FindBugsSummary>
			  <ClassFeatures></ClassFeatures>
			  <History></History>
			</BugCollection>`

		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(output, nil)

		analysis := AnalysisMock()

		assert.NotPanics(t, func() {
			service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, config, &horusec.Monitor{})

			NewFormatter(service).StartAnalysis("")
		})
	})
}
