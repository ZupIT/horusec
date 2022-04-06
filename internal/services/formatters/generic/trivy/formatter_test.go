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

package trivy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ZupIT/horusec-devkit/pkg/entities/analysis"
	"github.com/ZupIT/horusec-devkit/pkg/enums/languages"
	"github.com/ZupIT/horusec-devkit/pkg/enums/tools"
	"github.com/stretchr/testify/assert"

	"github.com/ZupIT/horusec/config"
	"github.com/ZupIT/horusec/internal/entities/toolsconfig"
	"github.com/ZupIT/horusec/internal/services/formatters"
	"github.com/ZupIT/horusec/internal/utils/testutil"
)

func TestTrivyParseOutput(t *testing.T) {
	dirName := filepath.Join(".horusec", "00000000-0000-0000-0000-000000000000")
	err := os.MkdirAll(dirName, 0o777)
	assert.NoError(t, err)
	file, err := os.Create(filepath.Join(dirName, "go.sum"))
	defer file.Close()
	assert.NoError(t, err)
	t.Cleanup(func() {
		err = os.RemoveAll(".horusec")
		assert.NoError(t, err)
	})
	t.Run("Should add 153 vulnerabilities from FileSystemOutput and ConfigOutput on analysis without errors", func(t *testing.T) {
		const totalVulnerabilitiesExpected = 153
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(configOutput, nil).Once()
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return(fileSystemOutput, nil).Once()

		newAnalysis := new(analysis.Analysis)

		cfg := config.New()

		service := formatters.NewFormatterService(newAnalysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
		assert.Len(t, newAnalysis.AnalysisVulnerabilities, totalVulnerabilitiesExpected)
		hashesValidated := make(map[string]int, 0)
		for _, v := range newAnalysis.AnalysisVulnerabilities {
			if hashesValidated[v.Vulnerability.VulnHash] == 0 {
				hashesValidated[v.Vulnerability.VulnHash] = 1
			} else {
				hashesValidated[v.Vulnerability.VulnHash]++
			}
			vuln := v.Vulnerability
			assert.Equal(t, tools.Trivy, vuln.SecurityTool)
			assert.Equal(t, languages.Generic, vuln.Language)
			assert.NotEmpty(t, vuln.Details, "Expected not empty details")
			assert.NotEmpty(t, vuln.Code, "Expected not empty code")
			assert.NotEmpty(t, vuln.File, "Expected not empty file name")
			assert.NotEmpty(t, vuln.Severity, "Expected not empty severity")
		}
		// Validation to check if only 10% of the vulnerabilities found there is hash duplicated
		totalDuplicated := 0
		for _, v := range hashesValidated {
			if v > 1 {
				totalDuplicated++
			}
		}
		percentageDuplicate := (totalDuplicated * 100) / totalVulnerabilitiesExpected
		const maxPercentageAcceptedDuplicated = 10
		assert.LessOrEqual(t, percentageDuplicate, maxPercentageAcceptedDuplicated)
	})

	t.Run("Should add error on analysis when invalid output", func(t *testing.T) {
		dockerAPIControllerMock := testutil.NewDockerMock()
		dockerAPIControllerMock.On("SetAnalysisID")
		dockerAPIControllerMock.On("CreateLanguageAnalysisContainer").Return("invalid", nil)

		analysis := new(analysis.Analysis)

		cfg := config.New()

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")

		assert.True(t, analysis.HasErrors(), "Expected errors on analysis")
	})

	t.Run("Should not execute tool because it's ignored", func(t *testing.T) {
		analysis := new(analysis.Analysis)

		dockerAPIControllerMock := testutil.NewDockerMock()

		cfg := config.New()
		cfg.ToolsConfig = toolsconfig.ToolsConfig{
			tools.Trivy: toolsconfig.Config{
				IsToIgnore: true,
			},
		}

		service := formatters.NewFormatterService(analysis, dockerAPIControllerMock, cfg)
		formatter := NewFormatter(service)
		formatter.StartAnalysis("")
	})
}

const fileSystemOutput = `
{
  "SchemaVersion": 2,
  "ArtifactName": ".",
  "ArtifactType": "filesystem",
  "Metadata": {
    "ImageConfig": {
      "architecture": "",
      "created": "0001-01-01T00:00:00Z",
      "os": "",
      "rootfs": {
        "type": "",
        "diff_ids": null
      },
      "config": {}
    }
  },
  "Results": [
    {
      "Target": "../../../../../../../examples/go/example1/go.sum",
      "Class": "lang-pkgs",
      "Type": "gomod",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2020-13949",
          "PkgName": "github.com/apache/thrift",
          "InstalledVersion": "0.13.0",
          "FixedVersion": "v0.14.0",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-13949",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "libthrift: potential DoS when processing untrusted payloads",
          "Description": "In Apache Thrift 0.9.3 to 0.13.0, malicious RPC clients could send short messages which would result in a large memory allocation, potentially leading to denial of service.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-13949",
            "https://github.com/advisories/GHSA-g2fg-mr77-6vrm",
            "https://github.com/apache/hbase/pull/2958",
            "https://lists.apache.org/thread.html/r01b34416677f1ba869525e1b891ac66fa6f88c024ee4d7cdea6b456b@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r02ba8db500d15a5949e9a7742815438002ba1cf1b361bdda52ed40ca@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r02f7771863383ae993eb83cdfb70c3cb65a355c913242c850f61f1b8@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r0372f0af2dad0b76fbd7a6cfdaad29d50384ad48dda475a5026ff9a3@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r08a7bd19470ef8950d58cc9d9e7b02bc69c43f56c601989a7729cce5@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r1084a911dff90b2733b442ee0f5929d19b168035d447f2d25f534fe4@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/r117d5d2b08d505b69558a2a31b0a1cf8990cd0385060b147e70e76a9@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r12090c81b67d21a814de6cf54428934a5e5613fde222759bbb05e99b@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/r13f40151513ff095a44a86556c65597a7e55c00f5e19764a05530266@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r143ca388b0c83fe659db14be76889d50b453b0ee06f423181f736933@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r1456eab5f3768be69436d5b0a68b483eb316eb85eb3ef6eba156a302@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r1504886a550426d3c05772c47b1a6350c3235e51fd1fdffbec43e974@%3Cuser.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/r15eed5d21e16a5cce810c1e096ffcffc36cd08c2f78ce2f9b24b4a6a@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/r179119bbfb5610499286a84c316f6789c5afbfa5340edec6eb28d027@%3Ccommits.druid.apache.org%3E",
            "https://lists.apache.org/thread.html/r17cca685ad53bc8300ee7fcfe874cb784a222343f217dd076e7dc1b6@%3Ccommits.camel.apache.org%3E",
            "https://lists.apache.org/thread.html/r18732bb1343894143d68db58fe4c8f56d9cd221b37f1378ed7373372@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r191a9279e2863b68e5496ee4ecd8be0d4fe43b324b934f0d1f106e1d@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r196409cc4df929d540a2e66169104f2b3b258d8bd96b5f083c59ee51@%3Ccommits.camel.apache.org%3E",
            "https://lists.apache.org/thread.html/r1d4a247329a8478073163567bbc8c8cb6b49c6bfc2bf58153a857af1@%3Ccommits.druid.apache.org%3E",
            "https://lists.apache.org/thread.html/r1dea91f0562e0a960b45b1c5635b2a47b258b77171334276bcf260a7@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r1fb2d26b81c64ce96c4fd42b9e6842ff315b02c36518213b6c057350@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r20f6f8f8cf07986dc5304baed3bf4d8a1c4cf135ff6fe3640be4d7ec@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/r278e96edc4bc13efb2cb1620a73e48f569162b833c6bda3e6ea18b80@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r27b7d3d95ffa8498899ef1c9de553d469f8fe857640a3f6e58dba640@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r286e9a13d3ab0550042997219101cb87871834b8d5ec293b0c60f009@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r298a25228868ebc0943d56c8f3641212a0962d2dbcf1507d5860038e@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r2d180180f37c2ab5cebd711d080d01d8452efa8ad43c5d9cd7064621@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r2ed66a3823990306b742b281af1834b9bc85f98259c870b8ffb13d93@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r2f6a547f226579f542eb08793631d1f2d47d7aed7e2f9d11a4e6af9f@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r3550b61639688e0efbc253c6c3e6358851c1f053109f1c149330b535@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r36581cc7047f007dd6aadbdd34e18545ec2c1eb7ccdae6dd47a877a9@%3Ccommits.pulsar.apache.org%3E",
            "https://lists.apache.org/thread.html/r3a1291a7ab8ee43db87cb0253371489810877028fc6e7c68dc640926@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r3de0e0c26d4bd00dd28cab27fb44fba11d1c1d20275f7cce71393dd1@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r3e31ec7e8c39db7553be4f4fd4d27cf27c41f1ba9c985995c4ea9c5a@%3Cnotifications.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/r3f3e1d562c528b4bafef2dde51f79dd444a4b68ef24920d68068b6f9@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r3f97dbbbb1b2a7324521208bb595392853714e141a37b8f68d395835@%3Cnotifications.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/r409e296c890753296c544a74d4de0d4a3ce719207a5878262fa2bd71@%3Ccommits.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r421a9a76811c1aed7637b5fe5376ab14c09ccdd7b70d5211d6e76d1e@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r43dc2b2e928e9d845b07ac075634cb759d91bb852421dc282f87a74a%40%3Cdev.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/r449288f6a941a2585262e0f4454fdefe169d5faee33314f6f89fab30@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r4d90b6d8de9697beb38814596d3a0d4994fa9aba1f6731a2c648d3ae@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/r4fa53eacca2ac38904f38dc226caebb3f2f668b2da887f2fd416f4a7@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r515e01a30443cfa2dbb355c44c63149869afd684fb7b0344c58fa67b@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r533a172534ae67f6f17c4d33a1b814d3d5ada9ccd4eb442249f33fa2@%3Ccommits.camel.apache.org%3E",
            "https://lists.apache.org/thread.html/r587b4a5bcbc290269df0906bafba074f3fe4e50d4e959212f56fa7ea@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r62aa6d07b23095d980f348d330ed766560f9a9e940fec051f534ce37@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/r635133a74fa07ef3331cae49a9a088365922266edd58099a6162a5d3@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/r668aed02e287c93403e0b8df16089011ee4a96afc8f479809f1fc07f@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r6990c849aeafe65366794bfd002febd47b7ffa8cf3c059b400bbb11d@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r699c031e6921b0ad0f943848e7ba1d0e88c953619d47908618998f76@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r6ae3c68b0bfe430fb32f24236475276b6302bed625b23f53b68748b5@%3Cuser.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/r6ba4f0817f98bf7c1cb314301cb7a24ba11a0b3e7a5be8b0ae3190b0@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/r6c5b7324274fd361b038c5cc316e99344b7ae20beae7163214fac14d@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r72c3d1582d50b2ca7dd1ee97e81c847a5cf3458be26d42653c39d7a6@%3Ccommits.camel.apache.org%3E",
            "https://lists.apache.org/thread.html/r741364444c3b238ab4a161f67f0d3a8f68acc517a39e6a93aa85d753@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/r74eb88b422421c65514c23cb9c2b2216efb9254317ea1b6a264fe6dc@%3Ccommits.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r7597683cc8b87a31ec864835225a543dad112d7841bf1f17bf7eb8db@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r7ae909438ff5a2ffed9211e6ab0bd926396fd0b1fc33f31a406ee704@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r812915ecfa541ad2ca65c68a97b2c014dc87141dfaefc4de85049681@%3Ccommits.camel.apache.org%3E",
            "https://lists.apache.org/thread.html/r850522c56c05aa06391546bdb530bb8fc3437f2b77d16e571ae73309@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r869331422580d35b4e65bd74cf3090298c4651bf4f31bfb19ae769da@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/r886b6d9a89b6fa0aafbf0a8f8f14351548d6c6f027886a3646dbd075@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/r8897a41f50d4eb19b268bde99328e943ba586f77779efa6de720c39f@%3Ccommits.druid.apache.org%3E",
            "https://lists.apache.org/thread.html/r890b8ec5203d70a59a6b1289420d46938d9029ed706aa724978789be@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r89fdd39965efb7c6d22bc21c286d203252cea476e1782724aca0748e@%3Cuser.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/r8dfbefcd606af6737b62461a45a9af9222040b62eab474ff2287cf75@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r90b4473950e26607ed77f3d70f120166f6a36a3f80888e4eeabcaf91@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/r93f23f74315e009f4fb68ef7fc794dceee42cf87fe6613814dcd8c70@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r950ced188d62320fdb84d9e2c6ba896328194952eff7430c4f55e4b0@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/r995b945cc8f6ec976d8c52d42ba931a688b45fb32cbdde715b6a816a@%3Cuser.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/r9b51e7c253cb0989b4c03ed9f4e5f0478e427473357209ccc4d08ebf@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/r9ec75f690dd60fec8621ba992290962705d5b7f0d8fd0a42fab0ac9f@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/ra3f7f06a1759c8e2985ed24ae2f5483393c744c1956d661adc873f2c@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/ra7371efd8363c1cd0f5331aafd359a808cf7277472b8616d7b392128@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/ra9f7c755790313e1adb95d29794043fb102029e803daf4212ae18063@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/race178e9500ab8a5a6112667d27c48559150cadb60f2814bc67c40af@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rad635e16b300cf434280001ee6ecd2ed2c70987bf16eb862bfa86e02@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rada9d2244a66ede0be29afc5d5f178a209f9988db56b9b845d955741@%3Ccommits.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rae95c2234b6644bfd666b2671a1b42a09f38514d0f27cca3c7d5d55a@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/raea1bb8cf2eb39c5e10543f547bdbbdbb563c2ac6377652f161d4e37@%3Ccommits.druid.apache.org%3E",
            "https://lists.apache.org/thread.html/rb3574bc1036b577b265be510e6b208f0a5d5d84cd7198347dc8482df@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rb44ec04e5a9b1f87fef97bb5f054010cbfaa3b8586472a3a38a16fca@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rb51977d392b01434b0b5df5c19b9ad5b6178cfea59e676c14f24c053@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/rb91c32194eb5006f0b0c8bcdbd512c13495a1b277d4d51d45687f036@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/rbc5cad06a46d23253a3c819229efedecfc05f89ef53f5fdde77a86d6@%3Cuser.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/rbfbb81e7fb5d5009caf25798f02f42a7bd064a316097303ba2f9ed76@%3Ccommits.druid.apache.org%3E",
            "https://lists.apache.org/thread.html/rc48ab5455bdece9a4afab53ca0f1e4f742d5baacb241323454a87b4e@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rc7a241e0af086b226ff9ccabc4a243d206f0f887037994bfd8fcaaeb@%3Ccommits.druid.apache.org%3E",
            "https://lists.apache.org/thread.html/rc7a79b08822337c68705f16ee7ddcfd352313b836e78a4b86c7a7e3d@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rc896ce7761999b088f3adabcb99dde2102b6a66130b8eec6c8265eab@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rcace846f74ea9e2af2f7c30cef0796724aa74089f109c8029b850163@%3Cdev.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/rcae4c66f67e701db44d742156dee1f3e5e4e07ad7ce10c740a76b669@%3Cissues.hive.apache.org%3E",
            "https://lists.apache.org/thread.html/rcdf62ecd36e39e4ff9c61802eee4927ce9ecff1602eed1493977ef4c@%3Cuser.thrift.apache.org%3E",
            "https://lists.apache.org/thread.html/rd0734d91f16d5b050f0bcff78b4719300042a34fadf5e52d0edf898e@%3Cissues.solr.apache.org%3E",
            "https://lists.apache.org/thread.html/rd370fdb419652c5219409b315a6349b07a7e479bd3f151e9a5671774@%3Ccommits.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rd49d53b146d94a7d3a135f6b505589655ffec24ea470e345d31351bb@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rd78cdd87d84499a404202f015f55935db3658bd0983ecec81e6b18c6@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rdc8e0f92d06decaee5db58de4ded16d80016a7db2240a8db17225c49@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rdcf00186c34d69826d9c6b1f010136c98b00a586136de0061f7d267e@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rf568168e7f83871969928c0379813da6d034485f8b20fa73884816d6@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rf603d25213cfff81d6727c259328846b366fd32a43107637527c9768@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rf65df763f630163a3f620887efec082080555cee1adb0b8eaf2c7ddb@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rf741d08c7e0ab1542c81ea718467422bd01159ed284796a36ad88311@%3Cissues.hbase.apache.org%3E",
            "https://lists.apache.org/thread.html/rf75979ae0ffd526f3afa935a8f0ee13c82808ea8b2bc0325eb9dcd90@%3Ccommits.camel.apache.org%3E",
            "https://lists.apache.org/thread.html/rfbb01bb85cdc2022f3b96bdc416dbfcb49a2855b3a340aa88b2e1de9@%3Ccommits.druid.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-13949",
            "https://security.gentoo.org/glsa/202107-32",
            "https://www.oracle.com//security-alerts/cpujul2021.html",
            "https://www.oracle.com/security-alerts/cpujan2022.html"
          ],
          "PublishedDate": "2021-02-12T20:15:00Z",
          "LastModifiedDate": "2022-02-07T16:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-41103",
          "PkgName": "github.com/containerd/containerd",
          "InstalledVersion": "1.4.1",
          "FixedVersion": "v1.4.11, v1.5.7",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-41103",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "containerd: insufficiently restricted permissions on container root and plugin directories",
          "Description": "containerd is an open source container runtime with an emphasis on simplicity, robustness and portability. A bug was found in containerd where container root directories and some plugins had insufficiently restricted permissions, allowing otherwise unprivileged Linux users to traverse directory contents and execute programs. When containers included executable programs with extended permission bits (such as setuid), unprivileged Linux users could discover and execute those programs. When the UID of an unprivileged Linux user on the host collided with the file owner or group inside a container, the unprivileged Linux user on the host could discover, read, and modify those files. This vulnerability has been fixed in containerd 1.4.11 and containerd 1.5.7. Users should update to these version when they are released and may restart containers or update directory permissions to mitigate the vulnerability. Users unable to update should limit access to the host to trusted users. Update directory permission on container bundles directories.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-22"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.2,
              "V3Score": 7.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-41103",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41103",
            "https://github.com/containerd/containerd/commit/5b46e404f6b9f661a205e28d59c982d3634148f8",
            "https://github.com/containerd/containerd/security/advisories/GHSA-c2h3-6mxw-7mvq",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B5Q6G6I4W5COQE25QMC7FJY3I3PAYFBB/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZNFADTCHHYWVM6W4NJ6CB4FNFM2VMBIB/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41103",
            "https://ubuntu.com/security/notices/USN-5100-1",
            "https://www.debian.org/security/2021/dsa-5002"
          ],
          "PublishedDate": "2021-10-04T17:15:00Z",
          "LastModifiedDate": "2021-11-28T23:28:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-15257",
          "PkgName": "github.com/containerd/containerd",
          "InstalledVersion": "1.4.1",
          "FixedVersion": "1.2.0, 1.3.9, 1.4.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-15257",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "containerd: unrestricted access to abstract Unix domain socket can lead to privileges escalation",
          "Description": "containerd is an industry-standard container runtime and is available as a daemon for Linux and Windows. In containerd before versions 1.3.9 and 1.4.3, the containerd-shim API is improperly exposed to host network containers. Access controls for the shim’s API socket verified that the connecting process had an effective UID of 0, but did not otherwise restrict access to the abstract Unix domain socket. This would allow malicious containers running in the same network namespace as the shim, with an effective UID of 0 but otherwise reduced privileges, to cause new processes to be run with elevated privileges. This vulnerability has been fixed in containerd 1.3.9 and 1.4.3. Users should update to these versions as soon as they are released. It should be noted that containers started with an old version of containerd-shim should be stopped and restarted, as running containers will continue to be vulnerable even after an upgrade. If you are not providing the ability for untrusted users to start containers in the same network namespace as the shim (typically the \"host\" network namespace, for example with docker run --net=host or hostNetwork: true in a Kubernetes pod) and run with an effective UID of 0, you are not vulnerable to this issue. If you are running containers with a vulnerable configuration, you can deny access to all abstract sockets with AppArmor by adding a line similar to deny unix addr=@**, to your policy. It is best practice to run containers with a reduced set of privileges, with a non-zero UID, and with isolated namespaces. The containerd maintainers strongly advise against sharing namespaces with the host. Reducing the set of isolation mechanisms used for a container necessarily increases that container's privilege, regardless of what container runtime is used for running that container.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-669"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:L/Au:N/C:P/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
              "V2Score": 3.6,
              "V3Score": 5.2
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-15257",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15257",
            "https://github.com/advisories/GHSA-36xw-fx78-c5r4",
            "https://github.com/containerd/containerd/commit/4a4bb851f5da563ff6e68a83dc837c7699c469ad",
            "https://github.com/containerd/containerd/releases/tag/v1.4.3",
            "https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4",
            "https://linux.oracle.com/cve/CVE-2020-15257.html",
            "https://linux.oracle.com/errata/ELSA-2020-5966.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LNKXLOLZWO5FMAPX63ZL7JNKTNNT5NQD/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15257",
            "https://research.nccgroup.com/2020/12/10/abstract-shimmer-cve-2020-15257-host-networking-is-root-equivalent-again/",
            "https://security.gentoo.org/glsa/202105-33",
            "https://ubuntu.com/security/notices/USN-4653-1",
            "https://ubuntu.com/security/notices/USN-4653-2",
            "https://www.debian.org/security/2021/dsa-4865"
          ],
          "PublishedDate": "2020-12-01T03:15:00Z",
          "LastModifiedDate": "2022-01-01T18:11:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-21334",
          "PkgName": "github.com/containerd/containerd",
          "InstalledVersion": "1.4.1",
          "FixedVersion": "v1.3.10, v1.4.4",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-21334",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "containerd CRI plugin: information leak between containers via environment variables",
          "Description": "In containerd (an industry-standard container runtime) before versions 1.3.10 and 1.4.4, containers launched through containerd's CRI implementation (through Kubernetes, crictl, or any other pod/container client that uses the containerd CRI service) that share the same image may receive incorrect environment variables, including values that are defined for other containers. If the affected containers have different security contexts, this may allow sensitive information to be unintentionally shared. If you are not using containerd's CRI implementation (through one of the mechanisms described above), you are not vulnerable to this issue. If you are not launching multiple containers or Kubernetes pods from the same image which have different environment variables, you are not vulnerable to this issue. If you are not launching multiple containers or Kubernetes pods from the same image in rapid succession, you have reduced likelihood of being vulnerable to this issue This vulnerability has been fixed in containerd 1.3.10 and containerd 1.4.4. Users should update to these versions.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-668"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
              "V2Score": 4.3,
              "V3Score": 6.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
              "V3Score": 6.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-21334",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21334",
            "https://github.com/containerd/containerd/commit/05f951a3781f4f2c1911b05e61c160e9c30eaa8e",
            "https://github.com/containerd/containerd/releases/tag/v1.3.10",
            "https://github.com/containerd/containerd/releases/tag/v1.4.4",
            "https://github.com/containerd/containerd/security/advisories/GHSA-6g2q-w5j3-fwh4",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KUE2Z2ZUWBHRU36ZGBD2YSJCYB6ELPXE/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QIBPKSX5IOWPM3ZPFB3JVLXWDHSZTTWT/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VTXHA5JOWQRCCUZH7ZQBEYN6KZKJEYSD/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-21334",
            "https://security.gentoo.org/glsa/202105-33",
            "https://ubuntu.com/security/notices/USN-4881-1"
          ],
          "PublishedDate": "2021-03-10T22:15:00Z",
          "LastModifiedDate": "2021-05-26T12:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-32760",
          "PkgName": "github.com/containerd/containerd",
          "InstalledVersion": "1.4.1",
          "FixedVersion": "v1.4.8, v1.5.4",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-32760",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "containerd: pulling and extracting crafted container image may result in Unix file permission changes",
          "Description": "containerd is a container runtime. A bug was found in containerd versions prior to 1.4.8 and 1.5.4 where pulling and extracting a specially-crafted container image can result in Unix file permission changes for existing files in the host’s filesystem. Changes to file permissions can deny access to the expected owner of the file, widen access to others, or set extended bits like setuid, setgid, and sticky. This bug does not directly allow files to be read, modified, or executed without an additional cooperating process. This bug has been fixed in containerd 1.5.4 and 1.4.8. As a workaround, ensure that users only pull images from trusted sources. Linux security modules (LSMs) like SELinux and AppArmor can limit the files potentially affected by this bug through policies and profiles that prevent containerd from interacting with specific files.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-668"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
              "V2Score": 6.8,
              "V3Score": 6.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-32760",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32760",
            "https://github.com/containerd/containerd/releases/tag/v1.4.8",
            "https://github.com/containerd/containerd/releases/tag/v1.5.4",
            "https://github.com/containerd/containerd/security/advisories/GHSA-c72p-9xmj-rx3w",
            "https://linux.oracle.com/cve/CVE-2021-32760.html",
            "https://linux.oracle.com/errata/ELSA-2021-9373.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDMNDPJJTP3J5GOEDB66F6MGXUTRG3Y3/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-32760",
            "https://ubuntu.com/security/notices/USN-5012-1"
          ],
          "PublishedDate": "2021-07-19T21:15:00Z",
          "LastModifiedDate": "2021-10-18T12:54:00Z"
        },
        {
          "VulnerabilityID": "GMS-2021-175",
          "PkgName": "github.com/containerd/containerd",
          "InstalledVersion": "1.4.1",
          "FixedVersion": "1.4.12, 1.5.8",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Ambiguous OCI manifest parsing",
          "Description": "In the OCI Distribution Specification version 1.0.0 and prior and in the OCI Image Specification version 1.0.1 and prior, manifest and index documents are ambiguous without an accompanying Content-Type HTTP header.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-5j5w-g665-5m35",
            "https://github.com/containerd/containerd/releases/tag/v1.4.12",
            "https://github.com/containerd/containerd/releases/tag/v1.5.8",
            "https://github.com/containerd/containerd/security/advisories/GHSA-5j5w-g665-5m35",
            "https://github.com/opencontainers/distribution-spec/security/advisories/GHSA-mc8v-mgrf-8f4m",
            "https://github.com/opencontainers/image-spec/security/advisories/GHSA-77vh-xpmg-72qh"
          ]
        },
        {
          "VulnerabilityID": "CVE-2020-26160",
          "PkgName": "github.com/dgrijalva/jwt-go",
          "InstalledVersion": "3.2.0+incompatible",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-26160",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "jwt-go: access restriction bypass vulnerability",
          "Description": "jwt-go before 4.0.0-preview1 allows attackers to bypass intended access restrictions in situations with []string{} for m[\"aud\"] (which is allowed by the specification). Because the type assertion fails, \"\" is the value of aud. This is a security problem if the JWT token is presented to a service that lacks its own audience check.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-862"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-26160",
            "https://github.com/dgrijalva/jwt-go/commit/ec0a89a131e3e8567adcb21254a5cd20a70ea4ab",
            "https://github.com/dgrijalva/jwt-go/issues/422",
            "https://github.com/dgrijalva/jwt-go/pull/426",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-26160",
            "https://pkg.go.dev/vuln/GO-2020-0017",
            "https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMDGRIJALVAJWTGO-596515"
          ],
          "PublishedDate": "2020-09-30T18:15:00Z",
          "LastModifiedDate": "2021-07-21T11:39:00Z"
        },
        {
          "VulnerabilityID": "GMS-2022-20",
          "PkgName": "github.com/docker/distribution",
          "InstalledVersion": "2.7.1+incompatible",
          "FixedVersion": "v2.8.0",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "OCI Manifest Type Confusion Issue",
          "Description": "### Impact\n\nSystems that rely on digest equivalence for image attestations may be vulnerable to type confusion.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-qq97-vm5h-rrhg",
            "https://github.com/distribution/distribution/commit/b59a6f827947f9e0e67df0cfb571046de4733586",
            "https://github.com/distribution/distribution/security/advisories/GHSA-qq97-vm5h-rrhg",
            "https://github.com/opencontainers/image-spec/pull/411"
          ]
        },
        {
          "VulnerabilityID": "CVE-2021-3121",
          "PkgName": "github.com/gogo/protobuf",
          "InstalledVersion": "1.3.1",
          "FixedVersion": "1.3.2",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-3121",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "gogo/protobuf: plugin/unmarshal/unmarshal.go lacks certain index validation",
          "Description": "An issue was discovered in GoGo Protobuf before 1.3.2. plugin/unmarshal/unmarshal.go lacks certain index validation, aka the \"skippy peanut butter\" issue.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-129"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
              "V2Score": 7.5,
              "V3Score": 8.6
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",
              "V3Score": 8.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-3121",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3121",
            "https://discuss.hashicorp.com/t/hcsec-2021-23-consul-exposed-to-denial-of-service-in-gogo-protobuf-dependency/29025",
            "https://github.com/gogo/protobuf/commit/b03c65ea87cdc3521ede29f62fe3ce239267c1bc",
            "https://github.com/gogo/protobuf/compare/v1.3.1...v1.3.2",
            "https://lists.apache.org/thread.html/r68032132c0399c29d6cdc7bd44918535da54060a10a12b1591328bff@%3Cnotifications.skywalking.apache.org%3E",
            "https://lists.apache.org/thread.html/r88d69555cb74a129a7bf84838073b61259b4a3830190e05a3b87994e@%3Ccommits.pulsar.apache.org%3E",
            "https://lists.apache.org/thread.html/rc1e9ff22c5641d73701ba56362fb867d40ed287cca000b131dcf4a44@%3Ccommits.pulsar.apache.org%3E",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3121",
            "https://pkg.go.dev/vuln/GO-2021-0053",
            "https://security.netapp.com/advisory/ntap-20210219-0006/"
          ],
          "PublishedDate": "2021-01-11T06:15:00Z",
          "LastModifiedDate": "2021-10-18T06:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-19794",
          "PkgName": "github.com/miekg/dns",
          "InstalledVersion": "1.0.14",
          "FixedVersion": "1.1.25-0.20191211073109-8ebf2e419df7",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19794",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "golang-github-miekg-dns: predictable TXID can lead to response forgeries",
          "Description": "The miekg Go DNS package before 1.1.25, as used in CoreDNS before 1.6.6 and other products, improperly generates random numbers because math/rand is used. The TXID becomes predictable, leading to response forgeries.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-338"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 4.3,
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-19794",
            "https://github.com/advisories/GHSA-44r7-7p62-q3fr",
            "https://github.com/coredns/coredns/issues/3519",
            "https://github.com/coredns/coredns/issues/3547",
            "https://github.com/miekg/dns/commit/8ebf2e419df7857ac8919baa05248789a8ffbf33",
            "https://github.com/miekg/dns/compare/v1.1.24...v1.1.25",
            "https://github.com/miekg/dns/issues/1037",
            "https://github.com/miekg/dns/issues/1043",
            "https://github.com/miekg/dns/pull/1044",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19794",
            "https://pkg.go.dev/vuln/GO-2020-0008"
          ],
          "PublishedDate": "2019-12-13T22:15:00Z",
          "LastModifiedDate": "2020-01-02T17:36:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-26892",
          "PkgName": "github.com/nats-io/jwt",
          "InstalledVersion": "0.3.2",
          "FixedVersion": "v1.1.0",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-26892",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "The JWT library in NATS nats-server before 2.1.9 has Incorrect Access  ...",
          "Description": "The JWT library in NATS nats-server before 2.1.9 has Incorrect Access Control because of how expired credentials are handled.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-798"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            }
          },
          "References": [
            "https://advisories.nats.io/CVE/CVE-2020-26892.txt",
            "https://github.com/advisories/GHSA-4w5x-x539-ppf5",
            "https://github.com/nats-io/jwt/security/advisories/GHSA-4w5x-x539-ppf5",
            "https://github.com/nats-io/nats-server/commit/1e08b67f08e18cd844dce833a265aaa72500a12f",
            "https://github.com/nats-io/nats-server/commits/master",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VT67XCLIIBYRT762SVFBYFFTQFVSM3SI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-26892",
            "https://www.openwall.com/lists/oss-security/2020/11/02/2"
          ],
          "PublishedDate": "2020-11-06T08:15:00Z",
          "LastModifiedDate": "2022-01-01T18:18:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-26521",
          "PkgName": "github.com/nats-io/jwt",
          "InstalledVersion": "0.3.2",
          "FixedVersion": "v1.1.0",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-26521",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "The JWT library in NATS nats-server before 2.1.9 allows a denial of se ...",
          "Description": "The JWT library in NATS nats-server before 2.1.9 allows a denial of service (a nil dereference in Go code).",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-476"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2020/11/02/2",
            "https://advisories.nats.io/CVE/CVE-2020-26521.txt",
            "https://github.com/advisories/GHSA-h2fg-54x9-5qhq",
            "https://github.com/nats-io/jwt/security/advisories/GHSA-h2fg-54x9-5qhq",
            "https://github.com/nats-io/nats-server/commit/9ff8bcde2e46009e98bd9e88f598af355f62c168",
            "https://github.com/nats-io/nats-server/commits/master",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VT67XCLIIBYRT762SVFBYFFTQFVSM3SI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-26521"
          ],
          "PublishedDate": "2020-11-06T08:15:00Z",
          "LastModifiedDate": "2022-01-01T18:18:00Z"
        },
        {
          "VulnerabilityID": "GMS-2022-72",
          "PkgName": "github.com/nats-io/jwt",
          "InstalledVersion": "0.3.2",
          "FixedVersion": "v2.0.1",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Import token permissions checking not enforced",
          "Description": "The NATS server provides for Subjects which are namespaced by Account; all Subjects are supposed to be private to an account, with an 'Export/Import' system used to grant cross-account access to some Subjects. Some Exports are public, such that anyone can import the relevant subjects, and some Exports are private, such that the Import requires a token JWT to prove permission. The JWT library's validation of the bindings in the 'Import Token' incorrectly warned on mismatches, instead of outright rejecting the token. As a result, any account can take an Import token used by any other account and re-use it for themselves because the binding to the importing account is not rejected, and use it to import any Subject from the Exporting account, not just the Subject referenced in the Import Token. The NATS account-server system treats account JWTs as semi-public information, such that an attacker can easily enumerate all account JWTs and retrieve all Import Tokens from those account JWTs.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-62mh-w5cv-p88c",
            "https://github.com/nats-io/jwt/security/advisories/GHSA-62mh-w5cv-p88c"
          ]
        },
        {
          "VulnerabilityID": "GMS-2022-73",
          "PkgName": "github.com/nats-io/jwt",
          "InstalledVersion": "0.3.2",
          "FixedVersion": "v2.0.1",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Import token permissions checking not enforced",
          "Description": "The NATS server provides for Subjects which are namespaced by Account; all Subjects are supposed to be private to an account, with an 'Export/Import' system used to grant cross-account access to some Subjects. Some Exports are public, such that anyone can import the relevant subjects, and some Exports are private, such that the Import requires a token JWT to prove permission. The JWT library's validation of the bindings in the 'Import Token' incorrectly warned on mismatches, instead of outright rejecting the token. As a result, any account can take an Import token used by any other account and re-use it for themselves because the binding to the importing account is not rejected, and use it to import any Subject from the Exporting account, not just the Subject referenced in the Import Token. The NATS account-server system treats account JWTs as semi-public information, such that an attacker can easily enumerate all account JWTs and retrieve all Import Tokens from those account JWTs.",
          "Severity": "UNKNOWN",
          "References": [
            "https://advisories.nats.io/CVE/CVE-2021-3127.txt",
            "https://github.com/advisories/GHSA-62mh-w5cv-p88c",
            "https://github.com/nats-io/jwt/security/advisories/GHSA-62mh-w5cv-p88c"
          ]
        },
        {
          "VulnerabilityID": "CVE-2020-26892",
          "PkgName": "github.com/nats-io/nats-server/v2",
          "InstalledVersion": "2.1.2",
          "FixedVersion": "2.1.9",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-26892",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "The JWT library in NATS nats-server before 2.1.9 has Incorrect Access  ...",
          "Description": "The JWT library in NATS nats-server before 2.1.9 has Incorrect Access Control because of how expired credentials are handled.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-798"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            }
          },
          "References": [
            "https://advisories.nats.io/CVE/CVE-2020-26892.txt",
            "https://github.com/advisories/GHSA-4w5x-x539-ppf5",
            "https://github.com/nats-io/jwt/security/advisories/GHSA-4w5x-x539-ppf5",
            "https://github.com/nats-io/nats-server/commit/1e08b67f08e18cd844dce833a265aaa72500a12f",
            "https://github.com/nats-io/nats-server/commits/master",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VT67XCLIIBYRT762SVFBYFFTQFVSM3SI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-26892",
            "https://www.openwall.com/lists/oss-security/2020/11/02/2"
          ],
          "PublishedDate": "2020-11-06T08:15:00Z",
          "LastModifiedDate": "2022-01-01T18:18:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-26521",
          "PkgName": "github.com/nats-io/nats-server/v2",
          "InstalledVersion": "2.1.2",
          "FixedVersion": "2.1.9",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-26521",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "The JWT library in NATS nats-server before 2.1.9 allows a denial of se ...",
          "Description": "The JWT library in NATS nats-server before 2.1.9 allows a denial of service (a nil dereference in Go code).",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-476"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2020/11/02/2",
            "https://advisories.nats.io/CVE/CVE-2020-26521.txt",
            "https://github.com/advisories/GHSA-h2fg-54x9-5qhq",
            "https://github.com/nats-io/jwt/security/advisories/GHSA-h2fg-54x9-5qhq",
            "https://github.com/nats-io/nats-server/commit/9ff8bcde2e46009e98bd9e88f598af355f62c168",
            "https://github.com/nats-io/nats-server/commits/master",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VT67XCLIIBYRT762SVFBYFFTQFVSM3SI/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-26521"
          ],
          "PublishedDate": "2020-11-06T08:15:00Z",
          "LastModifiedDate": "2022-01-01T18:18:00Z"
        },
        {
          "VulnerabilityID": "CVE-2022-24450",
          "PkgName": "github.com/nats-io/nats-server/v2",
          "InstalledVersion": "2.1.2",
          "FixedVersion": "2.7.2",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-24450",
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "nats-server: misusing the \"dynamically provisioned sandbox accounts\" feature  authenticated user can obtain the privileges of the System account",
          "Description": "NATS nats-server before 2.7.2 has Incorrect Access Control. Any authenticated user can obtain the privileges of the System account by misusing the \"dynamically provisioned sandbox accounts\" feature.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-863"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:C/I:C/A:C",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 9,
              "V3Score": 8.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 8.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-24450",
            "https://advisories.nats.io/CVE/CVE-2022-24450.txt",
            "https://github.com/advisories/GHSA-g6w6-r76c-28j7",
            "https://github.com/nats-io/nats-server/releases/tag/v2.7.2",
            "https://github.com/nats-io/nats-server/security/advisories/GHSA-g6w6-r76c-28j7",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-24450"
          ],
          "PublishedDate": "2022-02-08T02:15:00Z",
          "LastModifiedDate": "2022-02-11T15:59:00Z"
        },
        {
          "VulnerabilityID": "GMS-2021-96",
          "PkgName": "github.com/nats-io/nats-server/v2",
          "InstalledVersion": "2.1.2",
          "FixedVersion": "2.1.9",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Incorrect handling of credential expiry by NATS Server",
          "Description": "(This advisory is canonically https://advisories.nats.io/CVE/CVE-2020-26892.txt )\n\n## Problem Description\n\nNATS nats-server through 2020-10-07 has Incorrect Access Control because of how expired credentials are handled.\n\nThe NATS accounts system has expiration timestamps on credentials; the \u003chttps://github.com/nats-io/jwt\u003e library had an API which encouraged misuse and an 'IsRevoked()' method which misused its own API.\n\nA new 'IsClaimRevoked()' method has correct handling and the nats-server has been updated to use this.  The old 'IsRevoked()' method now always returns true and other client code will have to be updated to avoid calling it.\n\nThe CVE identifier should cover any application using the old JWT API, where the nats-server is one of those applications.\n\n\n## Affected versions\n\n#### JWT library\n\n * all versions prior to 1.1.0\n * fixed after nats-io/jwt PR 103 landed (2020-10-06)\n\n#### NATS Server\n\n * Version 2 prior to 2.1.9\n   + 2.0.0 through and including 2.1.8 are vulnerable.\n * fixed with nats-io/nats-server PRs 1632, 1635, 1645\n\n\n## Impact\n\nTime-based credential expiry did not work.\n\n\n## Workaround\n\nHave credentials which only expire after fixes can be deployed.\n\n\n## Solution\n\nUpgrade the JWT dependency in any application using it.\n\nUpgrade the NATS server if using NATS Accounts.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-2c64-vj8g-vwrq",
            "https://github.com/nats-io/nats-server/security/advisories/GHSA-2c64-vj8g-vwrq"
          ]
        },
        {
          "VulnerabilityID": "GMS-2021-97",
          "PkgName": "github.com/nats-io/nats-server/v2",
          "InstalledVersion": "2.1.2",
          "FixedVersion": "2.2.0",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Import loops in account imports, nats-server DoS",
          "Description": "(This advisory is canonically \u003chttps://advisories.nats.io/CVE/CVE-2020-28466.txt\u003e)\n\n## Problem Description\n\nAn export/import cycle between accounts could crash the nats-server, after consuming CPU and memory.\n\nThis issue was fixed publicly in \u003chttps://github.com/nats-io/nats-server/pull/1731\u003e in November 2020.\n\nThe need to call this out as a security issue was highlighted by 'snyk.io' and we are grateful for their assistance in doing so.\n\nOrganizations which run a NATS service providing access to accounts run by untrusted third parties are affected.\nSee below for an important caveat if running such a service.\n\n\n## Affected versions\n\n#### NATS Server\n\n * Version 2 prior to 2.2.0\n   + 2.0.0 through and including 2.1.9 are vulnerable.\n * fixed with nats-io/nats-server PR 1731, commit 2e3c226729\n\n\n## Impact\n\nThe nats-server could be killed, after consuming resources.\n\n\n## Workaround\n\nThe import cycle requires at least two accounts to work; if you have open account sign-up, then restricting new account sign-up might hinder an attacker.\n\n\n## Solution\n\nUpgrade the nats-server.\n\n\n## Caveat on NATS with untrusted users\n\nRunning a NATS service which is exposed to untrusted users presents a heightened risk.\n\nAny remote execution flaw or equivalent seriousness, or denial-of-service by unauthenticated users, will lead to prompt releases by the NATS maintainers.\n\nFixes for denial of service issues with no threat of remote execution, when limited to account holders, are likely to just be committed to the main development branch with no special attention.\n\nThose who are running such services are encouraged to build regularly from git.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-gwj5-3vfq-q992",
            "https://github.com/nats-io/nats-server/security/advisories/GHSA-gwj5-3vfq-q992"
          ]
        },
        {
          "VulnerabilityID": "GMS-2021-98",
          "PkgName": "github.com/nats-io/nats-server/v2",
          "InstalledVersion": "2.1.2",
          "FixedVersion": "2.1.9",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Nil dereference in NATS JWT, DoS of nats-server",
          "Description": "(This advisory is canonically \u003chttps://advisories.nats.io/CVE/CVE-2020-26521.txt\u003e)\n\n## Problem Description\n\nThe NATS account system has an Operator trusted by the servers, which signs Accounts, and each Account can then create and sign Users within their account.  The Operator should be able to safely issue Accounts to other entities which it does not fully trust.\n\nA malicious Account could create and sign a User JWT with a state not created by the normal tooling, such that decoding by the NATS JWT library (written in Go) would attempt a nil dereference, aborting execution.\n\nThe NATS Server is known to be impacted by this.\n\n\n## Affected versions\n\n#### JWT library\n\n * all versions prior to 1.1.0\n\n#### NATS Server\n\n * Version 2 prior to 2.1.9\n\n\n## Impact\n\n#### JWT library\n\n * Programs would nil dereference and panic, aborting execution by default.\n\n#### NATS server\n\n * Denial of Service caused by process termination\n\n\n## Workaround\n\nIf your NATS servers do not trust any accounts which are managed by untrusted entities, then malformed User credentials are unlikely to be encountered.\n\n\n## Solution\n\nUpgrade the JWT dependency in any application using it.\n\nUpgrade the NATS server if using NATS Accounts.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-hmm9-r2m2-qg9w",
            "https://github.com/nats-io/nats-server/security/advisories/GHSA-hmm9-r2m2-qg9w"
          ]
        },
        {
          "VulnerabilityID": "GMS-2021-99",
          "PkgName": "github.com/nats-io/nats-server/v2",
          "InstalledVersion": "2.1.2",
          "FixedVersion": "2.2.0",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Import token permissions checking not enforced",
          "Description": "(This advisory is canonically \u003chttps://advisories.nats.io/CVE/CVE-2021-3127.txt\u003e)\n\n## Problem Description\n\nThe NATS server provides for Subjects which are namespaced by Account; all Subjects are supposed to be private to an account, with an Export/Import system used to grant cross-account access to some Subjects.  Some Exports are public, such that anyone can import the\nrelevant subjects, and some Exports are private, such that the Import requires a token JWT to prove permission.\n\nThe JWT library's validation of the bindings in the Import Token incorrectly warned on mismatches, instead of outright rejecting the token.\n\nAs a result, any account can take an Import token used by any other account and re-use it for themselves because the binding to the\nimporting account is not rejected, and use it to import *any* Subject from the Exporting account, not just the Subject referenced in the Import Token.\n\nThe NATS account-server system treats account JWTs as semi-public information, such that an attacker can easily enumerate all account JWTs and retrieve all Import Tokens from those account JWTs.\n\nThe CVE identifier should cover the JWT library repair and the nats-server containing the fixed JWT library, and any other application depending upon the fixed JWT library.\n\n\n## Affected versions\n\n#### JWT library\n\n * all versions prior to 2.0.1\n * fixed after nats-io/jwt#149 landed (2021-03-14)\n\n#### NATS Server\n\n * Version 2 prior to 2.2.0\n   + 2.0.0 through and including 2.1.9 are vulnerable\n * fixed with nats-io/nats-server@423b79440c (2021-03-14)\n\n\n## Impact\n\nIn deployments with untrusted accounts able to update the Account Server with imports, a malicious account can access any Subject from an account which provides Exported Subjects.\n\nAbuse of this facility requires the malicious actor to upload their tampered Account JWT to the Account Server, providing the service operator with a data-store which can be scanned for signs of abuse.\n\n\n## Workaround\n\nDeny access to clients to update their account JWT in the account server.\n\n\n## Solution\n\nUpgrade the JWT dependency in any application using it.\n\nUpgrade the NATS server if using NATS Accounts (with private Exports; Account owners can create those at any time though).\n\nAudit all accounts JWTs to scan for exploit attempts; a Python script to audit the accounts can be found at \u003chttps://gist.github.com/philpennock/09d49524ad98043ff11d8a40c2bb0d5a\u003e.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-j756-f273-xhp4",
            "https://github.com/nats-io/nats-server/security/advisories/GHSA-j756-f273-xhp4"
          ]
        },
        {
          "VulnerabilityID": "GMS-2021-101",
          "PkgName": "github.com/opencontainers/image-spec",
          "InstalledVersion": "1.0.1",
          "FixedVersion": "1.0.2",
          "Layer": {},
          "DataSource": {
            "ID": "glad",
            "Name": "GitLab Advisory Database Community",
            "URL": "https://gitlab.com/gitlab-org/advisories-community"
          },
          "Title": "Clarify 'mediaType' handling",
          "Description": "### Impact\nIn the OCI Image Specification version 1.0.1 and prior, manifest and index documents are not self-describing and documents with a single digest could be interpreted as either a manifest or an index.\n\n### Patches\nThe Image Specification will be updated to recommend that both manifest and index documents contain a 'mediaType' field to identify the type of document.",
          "Severity": "UNKNOWN",
          "References": [
            "https://github.com/advisories/GHSA-77vh-xpmg-72qh",
            "https://github.com/opencontainers/distribution-spec/security/advisories/GHSA-mc8v-mgrf-8f4m",
            "https://github.com/opencontainers/image-spec/commit/693428a734f5bab1a84bd2f990d92ef1111cd60c",
            "https://github.com/opencontainers/image-spec/releases/tag/v1.0.2",
            "https://github.com/opencontainers/image-spec/security/advisories/GHSA-77vh-xpmg-72qh"
          ]
        },
        {
          "VulnerabilityID": "CVE-2021-3538",
          "PkgName": "github.com/satori/go.uuid",
          "InstalledVersion": "1.2.0",
          "FixedVersion": "1.2.1-0.20181016170032-d91630c85102",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-3538",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "satori/go.uuid: predictable UUIDs generated via insecure randomness",
          "Description": "A flaw was found in github.com/satori/go.uuid in versions from commit 0ef6afb2f6cdd6cdaeee3885a95099c63f18fc8c to d91630c8510268e75203009fe7daf2b8e1d60c45. Due to insecure randomness in the g.rand.Read function the generated UUIDs are predictable for an attacker.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-338"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-3538",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1954376",
            "https://github.com/satori/go.uuid/commit/d91630c8510268e75203009fe7daf2b8e1d60c45",
            "https://github.com/satori/go.uuid/issues/73",
            "https://github.com/satori/go.uuid/pull/75",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-3538",
            "https://pkg.go.dev/vuln/GO-2020-0018",
            "https://snyk.io/vuln/SNYK-GOLANG-GITHUBCOMSATORIGOUUID-72488"
          ],
          "PublishedDate": "2021-06-02T14:15:00Z",
          "LastModifiedDate": "2021-06-14T13:37:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-20329",
          "PkgName": "go.mongodb.org/mongo-driver",
          "InstalledVersion": "1.1.0",
          "FixedVersion": "1.5.1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-20329",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Title": "mongo-go-driver: specific cstrings input may not be properly validated",
          "Description": "Specific cstrings input may not be properly validated in the MongoDB Go Driver when marshalling Go objects into BSON. A malicious user could use a Go object with specific string to potentially inject additional fields into marshalled documents. This issue affects all MongoDB GO Drivers up to (and including) 1.5.0.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 4,
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
              "V3Score": 6.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-20329",
            "https://github.com/advisories/GHSA-f6mq-5m25-4r72",
            "https://github.com/mongodb/mongo-go-driver/commit/2aca31d5986a9e1c65a92264736de9fdc3b9b4ca",
            "https://github.com/mongodb/mongo-go-driver/pull/622",
            "https://github.com/mongodb/mongo-go-driver/releases/tag/v1.5.1",
            "https://jira.mongodb.org/browse/GODRIVER-1923",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-20329",
            "https://pkg.go.dev/vuln/GO-2021-0112"
          ],
          "PublishedDate": "2021-06-10T17:15:00Z",
          "LastModifiedDate": "2021-06-23T17:10:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-38561",
          "PkgName": "golang.org/x/text",
          "InstalledVersion": "0.3.4",
          "FixedVersion": "0.3.7",
          "Layer": {},
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-38561",
          "DataSource": {
            "ID": "go-vulndb",
            "Name": "The Go Vulnerability Database",
            "URL": "https://github.com/golang/vulndb"
          },
          "Description": "Due to improper index calculation, an incorrectly formatted language tag can cause Parse\nto panic via an out of bounds read. If Parse is used to process untrusted user inputs,\nthis may be used as a vector for a denial of service attack.\n",
          "Severity": "UNKNOWN",
          "References": [
            "https://go-review.googlesource.com/c/text/+/340830",
            "https://go.googlesource.com/text/+/383b2e75a7a4198c42f8f87833eefb772868a56f",
            "https://pkg.go.dev/vuln/GO-2021-0113"
          ]
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/javascript/example1/package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2016-1000236",
          "PkgName": "cookie-signature",
          "InstalledVersion": "1.0.3",
          "FixedVersion": "\u003e=1.0.6",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-1000236",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-cookie-signature: Timing attack vulnerability",
          "Description": "Node-cookie-signature before 1.0.6 is affected by a timing attack due to the type of comparison used.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-362"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:S/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 3.5,
              "V3Score": 4.4
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:S/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:N",
              "V2Score": 3.5,
              "V3Score": 5.4
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2016-1000236",
            "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=838618",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1371409",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-1000236",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1000236",
            "https://github.com/advisories/GHSA-92vm-wfm5-mxvv",
            "https://github.com/tj/node-cookie-signature/commit/2c4df6b6cee540f30876198cd0b5bebf28528c07",
            "https://github.com/tj/node-cookie-signature/commit/39791081692e9e14aa62855369e1c7f80fbfd50e",
            "https://github.com/tj/node-cookie-signature/commit/4cc5e21e7f59a4ea0b51cd5e9634772d48fab590",
            "https://nodesecurity.io/advisories/134",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-1000236",
            "https://security-tracker.debian.org/tracker/CVE-2016-1000236",
            "https://travis-ci.com/nodejs/security-wg/builds/76423102",
            "https://www.mail-archive.com/secure-testing-team@lists.alioth.debian.org/msg06583.html",
            "https://www.npmjs.com/advisories/134"
          ],
          "PublishedDate": "2019-11-19T17:15:00Z",
          "LastModifiedDate": "2019-11-21T18:05:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16137",
          "PkgName": "debug",
          "InstalledVersion": "0.8.1",
          "FixedVersion": "3.1.0, 2.6.9",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16137",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-debug: Regular expression Denial of Service",
          "Description": "The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the o formatter. It takes around 50k characters to block for 2 seconds making this a low severity issue.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16137",
            "https://github.com/advisories/GHSA-gxpj-cx7g-858c",
            "https://github.com/visionmedia/debug/issues/501",
            "https://github.com/visionmedia/debug/pull/504",
            "https://lists.apache.org/thread.html/r8ba4c628fba7181af58817d452119481adce4ba92e889c643e4c7dd3@%3Ccommits.netbeans.apache.org%3E",
            "https://lists.apache.org/thread.html/rb5ac16fad337d1f3bb7079549f97d8166d0ef3082629417c39f12d63@%3Cnotifications.netbeans.apache.org%3E",
            "https://nodesecurity.io/advisories/534",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16137",
            "https://www.npmjs.com/advisories/534"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-6393",
          "PkgName": "express",
          "InstalledVersion": "4.0.0",
          "FixedVersion": "\u003e=3.11 \u003c4, \u003e=4.5",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-6393",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "express: cross-site scripting via content-type header",
          "Description": "The Express web framework before 3.11 and 4.x before 4.5 for Node.js does not provide a charset field in HTTP Content-Type headers in 400 level responses, which might allow remote attackers to conduct cross-site scripting (XSS) attacks via characters in a non-standard encoding.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 6.1
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2014-6393",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1203190",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6393",
            "https://github.com/advisories/GHSA-gpvr-g6gh-9mc2",
            "https://nodesecurity.io/advisories/express-no-charset-in-content-type-header",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6393",
            "https://www.npmjs.com/advisories/8"
          ],
          "PublishedDate": "2017-08-09T18:29:00Z",
          "LastModifiedDate": "2021-07-30T16:36:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16119",
          "PkgName": "fresh",
          "InstalledVersion": "0.2.0",
          "FixedVersion": "0.5.2",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16119",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-fresh: Regular expression denial of service when parsing crafted user input",
          "Description": "Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16119",
            "https://github.com/advisories/GHSA-9qj9-36jm-prpv",
            "https://nodesecurity.io/advisories/526",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16119",
            "https://www.npmjs.com/advisories/526"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16119",
          "PkgName": "fresh",
          "InstalledVersion": "0.2.2",
          "FixedVersion": "0.5.2",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16119",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-fresh: Regular expression denial of service when parsing crafted user input",
          "Description": "Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16119",
            "https://github.com/advisories/GHSA-9qj9-36jm-prpv",
            "https://nodesecurity.io/advisories/526",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16119",
            "https://www.npmjs.com/advisories/526"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16138",
          "PkgName": "mime",
          "InstalledVersion": "1.2.11",
          "FixedVersion": "2.0.3, 1.4.1",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16138",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-mime: Regular expression Denial of Service",
          "Description": "The mime module \u003c 1.4.1, 2.0.1, 2.0.2 is vulnerable to regular expression denial of service when a mime lookup is performed on untrusted user input.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16138",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16138",
            "https://github.com/advisories/GHSA-wrvr-8mpx-r7pp",
            "https://github.com/broofa/node-mime/commit/1df903fdeb9ae7eaa048795b8d580ce2c98f40b0 (2.x)",
            "https://github.com/broofa/node-mime/commit/855d0c4b8b22e4a80b9401a81f2872058eae274d (1.x)",
            "https://github.com/broofa/node-mime/issues/167",
            "https://nodesecurity.io/advisories/535",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16138",
            "https://www.npmjs.com/advisories/535"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-10539",
          "PkgName": "negotiator",
          "InstalledVersion": "0.3.0",
          "FixedVersion": "0.6.1",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-10539",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "negotiator is an HTTP content negotiator for Node.js and is used by ma ...",
          "Description": "negotiator is an HTTP content negotiator for Node.js and is used by many modules and frameworks including Express and Koa. The header for \"Accept-Language\", when parsed by negotiator 0.6.0 and earlier is vulnerable to Regular Expression Denial of Service via a specially crafted string.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10539",
            "https://github.com/advisories/GHSA-7mc5-chhp-fmc3",
            "https://nodesecurity.io/advisories/106",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-10539",
            "https://www.npmjs.com/advisories/106"
          ],
          "PublishedDate": "2018-05-31T20:29:00Z",
          "LastModifiedDate": "2019-10-09T23:16:00Z"
        },
        {
          "VulnerabilityID": "NSWG-ECO-106",
          "PkgName": "negotiator",
          "InstalledVersion": "0.3.0",
          "FixedVersion": "\u003e= 0.6.1",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "Regular Expression Denial of Service",
          "Description": "negotiator is an HTTP content negotiator for Node.js and is used by many modules and frameworks including Express and Koa.\n\nThe header for \"Accept-Language\", when parsed by negotiator is vulnerable to Regular Expression Denial of Service via a specially crafted string. \n\nTimeline\n\n- April 29th 2016 - Initial report to maintainers\n- April 29th 2016 - Confirm receipt from maintainers\n- May 1st 2016 - Fix confirmed\n- May 5th 2016 - 0.6.1 published with fix\n- June 16th 2016 - Advisory published (delay was to coordinate fixes in upstream frameworks, Koa and Express)",
          "Severity": "HIGH",
          "References": [
            "https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS"
          ]
        },
        {
          "VulnerabilityID": "CVE-2014-10064",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "1.0.0",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-10064",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "The qs module before 1.0.0 does not have an option or default for spec ...",
          "Description": "The qs module before 1.0.0 does not have an option or default for specifying object depth and when parsing a string representing a deeply nested object will block the event loop for long periods of time. An attacker could leverage this to cause a temporary denial-of-service condition, for example, in a web application, other requests would not be processed while this blocking is occurring.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "https://github.com/advisories/GHSA-f9cm-p3w6-xvr3",
            "https://nodesecurity.io/advisories/28",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-10064",
            "https://www.npmjs.com/advisories/28"
          ],
          "PublishedDate": "2018-05-31T20:29:00Z",
          "LastModifiedDate": "2019-10-09T23:09:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-7191",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "\u003e= 1.x",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-7191",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-qs: Denial-of-Service Memory Exhaustion",
          "Description": "The qs module before 1.0.0 in Node.js does not call the compact function for array data, which allows remote attackers to cause a denial of service (memory consumption) by using a large index value to create a sparse array.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://secunia.com/advisories/60026",
            "http://secunia.com/advisories/62170",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21685987",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687263",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687928",
            "https://access.redhat.com/errata/RHSA-2016:1380",
            "https://access.redhat.com/security/cve/CVE-2014-7191",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/96729",
            "https://github.com/advisories/GHSA-jjv7-qpx3-h62q",
            "https://github.com/raymondfeng/node-querystring/commit/43a604b7847e56bba49d0ce3e222fe89569354d8",
            "https://github.com/visionmedia/node-querystring/issues/104",
            "https://nodesecurity.io/advisories/qs_dos_memory_exhaustion",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-7191",
            "https://www.npmjs.com/advisories/29"
          ],
          "PublishedDate": "2014-10-19T01:55:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-1000048",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "6.3.2, 6.2.3, 6.1.2, 6.0.4",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-1000048",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-qs: Prototype override protection bypass",
          "Description": "the web framework using ljharb's qs module older than v6.3.2, v6.2.3, v6.1.2, and v6.0.4 is vulnerable to a DoS. A malicious user can send a evil request to cause the web framework crash.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2017:2672",
            "https://access.redhat.com/security/cve/CVE-2017-1000048",
            "https://github.com/advisories/GHSA-gqgv-6jq5-jjj9",
            "https://github.com/ljharb/qs/commit/beade029171b8cef9cee0d03ebe577e2dd84976d",
            "https://github.com/ljharb/qs/issues/200",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-1000048",
            "https://snyk.io/vuln/npm:qs:20170213",
            "https://www.npmjs.com/advisories/1469"
          ],
          "PublishedDate": "2017-07-17T13:18:00Z",
          "LastModifiedDate": "2017-12-31T02:29:00Z"
        },
        {
          "VulnerabilityID": "NSWG-ECO-28",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "\u003e= 1.x",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "Denial-of-Service Extended Event Loop Blocking",
          "Description": "The qs module does not have an option or default for specifying object depth and when parsing a string representing a deeply nested object will block the event loop for long periods of time. An attacker could leverage this to cause a temporary denial-of-service condition, for example, in a web application, other requests would not be processed while this blocking is occurring.",
          "Severity": "MEDIUM"
        },
        {
          "VulnerabilityID": "CVE-2014-6394",
          "PkgName": "send",
          "InstalledVersion": "0.1.4",
          "FixedVersion": "\u003e= 0.8.4",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-6394",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-send: directory traversal vulnerability",
          "Description": "visionmedia send before 0.8.4 for Node.js uses a partial comparison for verifying whether a directory is within the document root, which allows remote attackers to access restricted directories, as demonstrated using \"public-restricted\" under a \"public\" directory.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-22"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V2Score": 7.5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
              "V2Score": 2.6
            }
          },
          "References": [
            "http://lists.apple.com/archives/security-announce/2015/Sep/msg00002.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/139938.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/140020.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-September/139415.html",
            "http://secunia.com/advisories/62170",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687263",
            "http://www.openwall.com/lists/oss-security/2014/09/24/1",
            "http://www.openwall.com/lists/oss-security/2014/09/30/10",
            "http://www.securityfocus.com/bid/70100",
            "https://access.redhat.com/security/cve/CVE-2014-6394",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1146063",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6394",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/96727",
            "https://github.com/advisories/GHSA-xwg4-93c6-3h42",
            "https://github.com/visionmedia/send/commit/9c6ca9b2c0b880afd3ff91ce0d211213c5fa5f9a",
            "https://github.com/visionmedia/send/pull/59",
            "https://nodesecurity.io/advisories/send-directory-traversal",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6394",
            "https://support.apple.com/HT205217",
            "https://www.npmjs.com/advisories/32"
          ],
          "PublishedDate": "2014-10-08T17:55:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-8859",
          "PkgName": "send",
          "InstalledVersion": "0.1.4",
          "FixedVersion": "\u003e=0.11.1",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-8859",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "The send package before 0.11.1 for Node.js allows attackers to obtain  ...",
          "Description": "The send package before 0.11.1 for Node.js allows attackers to obtain the root path via unspecified vectors.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2016/04/20/11",
            "http://www.securityfocus.com/bid/96435",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8859",
            "https://github.com/advisories/GHSA-jgqf-hwc5-hh37",
            "https://github.com/expressjs/serve-static/blob/master/HISTORY.md#181--2015-01-20",
            "https://github.com/pillarjs/send/pull/70",
            "https://nodesecurity.io/advisories/56",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-8859",
            "https://www.npmjs.com/advisories/56"
          ],
          "PublishedDate": "2017-01-23T21:59:00Z",
          "LastModifiedDate": "2017-03-02T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-6394",
          "PkgName": "send",
          "InstalledVersion": "0.2.0",
          "FixedVersion": "\u003e= 0.8.4",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-6394",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-send: directory traversal vulnerability",
          "Description": "visionmedia send before 0.8.4 for Node.js uses a partial comparison for verifying whether a directory is within the document root, which allows remote attackers to access restricted directories, as demonstrated using \"public-restricted\" under a \"public\" directory.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-22"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V2Score": 7.5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
              "V2Score": 2.6
            }
          },
          "References": [
            "http://lists.apple.com/archives/security-announce/2015/Sep/msg00002.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/139938.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/140020.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-September/139415.html",
            "http://secunia.com/advisories/62170",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687263",
            "http://www.openwall.com/lists/oss-security/2014/09/24/1",
            "http://www.openwall.com/lists/oss-security/2014/09/30/10",
            "http://www.securityfocus.com/bid/70100",
            "https://access.redhat.com/security/cve/CVE-2014-6394",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1146063",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6394",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/96727",
            "https://github.com/advisories/GHSA-xwg4-93c6-3h42",
            "https://github.com/visionmedia/send/commit/9c6ca9b2c0b880afd3ff91ce0d211213c5fa5f9a",
            "https://github.com/visionmedia/send/pull/59",
            "https://nodesecurity.io/advisories/send-directory-traversal",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6394",
            "https://support.apple.com/HT205217",
            "https://www.npmjs.com/advisories/32"
          ],
          "PublishedDate": "2014-10-08T17:55:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-8859",
          "PkgName": "send",
          "InstalledVersion": "0.2.0",
          "FixedVersion": "\u003e=0.11.1",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-8859",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "The send package before 0.11.1 for Node.js allows attackers to obtain  ...",
          "Description": "The send package before 0.11.1 for Node.js allows attackers to obtain the root path via unspecified vectors.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2016/04/20/11",
            "http://www.securityfocus.com/bid/96435",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8859",
            "https://github.com/advisories/GHSA-jgqf-hwc5-hh37",
            "https://github.com/expressjs/serve-static/blob/master/HISTORY.md#181--2015-01-20",
            "https://github.com/pillarjs/send/pull/70",
            "https://nodesecurity.io/advisories/56",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-8859",
            "https://www.npmjs.com/advisories/56"
          ],
          "PublishedDate": "2017-01-23T21:59:00Z",
          "LastModifiedDate": "2017-03-02T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-1164",
          "PkgName": "serve-static",
          "InstalledVersion": "1.0.1",
          "FixedVersion": "~1.6.5, \u003e=1.7.2",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-1164",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "Open redirect vulnerability in the serve-static plugin before 1.7.2 fo ...",
          "Description": "Open redirect vulnerability in the serve-static plugin before 1.7.2 for Node.js, when mounted at the root, allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a // (slash slash) followed by a domain in the PATH_INFO to the default URI.",
          "Severity": "MEDIUM",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://nodesecurity.io/advisories/serve-static-open-redirect",
            "http://www.securityfocus.com/bid/72064",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1181917",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/99936",
            "https://github.com/advisories/GHSA-c3x7-gjmx-r2ff",
            "https://github.com/expressjs/serve-static/issues/26",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-1164",
            "https://snyk.io/vuln/npm:serve-static:20150113",
            "https://www.npmjs.com/advisories/35",
            "https://www.owasp.org/index.php/Open_redirect"
          ],
          "PublishedDate": "2015-01-21T15:28:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/javascript/example2/yarn.lock",
      "Class": "lang-pkgs",
      "Type": "yarn",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2016-1000236",
          "PkgName": "cookie-signature",
          "InstalledVersion": "1.0.3",
          "FixedVersion": "\u003e=1.0.6",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-1000236",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-cookie-signature: Timing attack vulnerability",
          "Description": "Node-cookie-signature before 1.0.6 is affected by a timing attack due to the type of comparison used.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-362"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:S/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 3.5,
              "V3Score": 4.4
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:S/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:N/A:N",
              "V2Score": 3.5,
              "V3Score": 5.4
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2016-1000236",
            "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=838618",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1371409",
            "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-1000236",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1000236",
            "https://github.com/advisories/GHSA-92vm-wfm5-mxvv",
            "https://github.com/tj/node-cookie-signature/commit/2c4df6b6cee540f30876198cd0b5bebf28528c07",
            "https://github.com/tj/node-cookie-signature/commit/39791081692e9e14aa62855369e1c7f80fbfd50e",
            "https://github.com/tj/node-cookie-signature/commit/4cc5e21e7f59a4ea0b51cd5e9634772d48fab590",
            "https://nodesecurity.io/advisories/134",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-1000236",
            "https://security-tracker.debian.org/tracker/CVE-2016-1000236",
            "https://travis-ci.com/nodejs/security-wg/builds/76423102",
            "https://www.mail-archive.com/secure-testing-team@lists.alioth.debian.org/msg06583.html",
            "https://www.npmjs.com/advisories/134"
          ],
          "PublishedDate": "2019-11-19T17:15:00Z",
          "LastModifiedDate": "2019-11-21T18:05:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16137",
          "PkgName": "debug",
          "InstalledVersion": "0.8.1",
          "FixedVersion": "3.1.0, 2.6.9",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16137",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-debug: Regular expression Denial of Service",
          "Description": "The debug module is vulnerable to regular expression denial of service when untrusted user input is passed into the o formatter. It takes around 50k characters to block for 2 seconds making this a low severity issue.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16137",
            "https://github.com/advisories/GHSA-gxpj-cx7g-858c",
            "https://github.com/visionmedia/debug/issues/501",
            "https://github.com/visionmedia/debug/pull/504",
            "https://lists.apache.org/thread.html/r8ba4c628fba7181af58817d452119481adce4ba92e889c643e4c7dd3@%3Ccommits.netbeans.apache.org%3E",
            "https://lists.apache.org/thread.html/rb5ac16fad337d1f3bb7079549f97d8166d0ef3082629417c39f12d63@%3Cnotifications.netbeans.apache.org%3E",
            "https://nodesecurity.io/advisories/534",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16137",
            "https://www.npmjs.com/advisories/534"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-6393",
          "PkgName": "express",
          "InstalledVersion": "4.0.0",
          "FixedVersion": "\u003e=3.11 \u003c4, \u003e=4.5",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-6393",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "express: cross-site scripting via content-type header",
          "Description": "The Express web framework before 3.11 and 4.x before 4.5 for Node.js does not provide a charset field in HTTP Content-Type headers in 400 level responses, which might allow remote attackers to conduct cross-site scripting (XSS) attacks via characters in a non-standard encoding.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 6.1
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2014-6393",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1203190",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6393",
            "https://github.com/advisories/GHSA-gpvr-g6gh-9mc2",
            "https://nodesecurity.io/advisories/express-no-charset-in-content-type-header",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6393",
            "https://www.npmjs.com/advisories/8"
          ],
          "PublishedDate": "2017-08-09T18:29:00Z",
          "LastModifiedDate": "2021-07-30T16:36:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16119",
          "PkgName": "fresh",
          "InstalledVersion": "0.2.0",
          "FixedVersion": "0.5.2",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16119",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-fresh: Regular expression denial of service when parsing crafted user input",
          "Description": "Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16119",
            "https://github.com/advisories/GHSA-9qj9-36jm-prpv",
            "https://nodesecurity.io/advisories/526",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16119",
            "https://www.npmjs.com/advisories/526"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16119",
          "PkgName": "fresh",
          "InstalledVersion": "0.2.2",
          "FixedVersion": "0.5.2",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16119",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-fresh: Regular expression denial of service when parsing crafted user input",
          "Description": "Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16119",
            "https://github.com/advisories/GHSA-9qj9-36jm-prpv",
            "https://nodesecurity.io/advisories/526",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16119",
            "https://www.npmjs.com/advisories/526"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16119",
          "PkgName": "fresh",
          "InstalledVersion": "0.2.4",
          "FixedVersion": "0.5.2",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16119",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-fresh: Regular expression denial of service when parsing crafted user input",
          "Description": "Fresh is a module used by the Express.js framework for HTTP response freshness testing. It is vulnerable to a regular expression denial of service when it is passed specially crafted input to parse. This causes the event loop to be blocked causing a denial of service condition.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16119",
            "https://github.com/advisories/GHSA-9qj9-36jm-prpv",
            "https://nodesecurity.io/advisories/526",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16119",
            "https://www.npmjs.com/advisories/526"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-16138",
          "PkgName": "mime",
          "InstalledVersion": "1.2.11",
          "FixedVersion": "2.0.3, 1.4.1",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-16138",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-mime: Regular expression Denial of Service",
          "Description": "The mime module \u003c 1.4.1, 2.0.1, 2.0.2 is vulnerable to regular expression denial of service when a mime lookup is performed on untrusted user input.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2017-16138",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16138",
            "https://github.com/advisories/GHSA-wrvr-8mpx-r7pp",
            "https://github.com/broofa/node-mime/commit/1df903fdeb9ae7eaa048795b8d580ce2c98f40b0 (2.x)",
            "https://github.com/broofa/node-mime/commit/855d0c4b8b22e4a80b9401a81f2872058eae274d (1.x)",
            "https://github.com/broofa/node-mime/issues/167",
            "https://nodesecurity.io/advisories/535",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-16138",
            "https://www.npmjs.com/advisories/535"
          ],
          "PublishedDate": "2018-06-07T02:29:00Z",
          "LastModifiedDate": "2019-10-09T23:24:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-10539",
          "PkgName": "negotiator",
          "InstalledVersion": "0.3.0",
          "FixedVersion": "0.6.1",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-10539",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "negotiator is an HTTP content negotiator for Node.js and is used by ma ...",
          "Description": "negotiator is an HTTP content negotiator for Node.js and is used by many modules and frameworks including Express and Koa. The header for \"Accept-Language\", when parsed by negotiator 0.6.0 and earlier is vulnerable to Regular Expression Denial of Service via a specially crafted string.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10539",
            "https://github.com/advisories/GHSA-7mc5-chhp-fmc3",
            "https://nodesecurity.io/advisories/106",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-10539",
            "https://www.npmjs.com/advisories/106"
          ],
          "PublishedDate": "2018-05-31T20:29:00Z",
          "LastModifiedDate": "2019-10-09T23:16:00Z"
        },
        {
          "VulnerabilityID": "NSWG-ECO-106",
          "PkgName": "negotiator",
          "InstalledVersion": "0.3.0",
          "FixedVersion": "\u003e= 0.6.1",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "Regular Expression Denial of Service",
          "Description": "negotiator is an HTTP content negotiator for Node.js and is used by many modules and frameworks including Express and Koa.\n\nThe header for \"Accept-Language\", when parsed by negotiator is vulnerable to Regular Expression Denial of Service via a specially crafted string. \n\nTimeline\n\n- April 29th 2016 - Initial report to maintainers\n- April 29th 2016 - Confirm receipt from maintainers\n- May 1st 2016 - Fix confirmed\n- May 5th 2016 - 0.6.1 published with fix\n- June 16th 2016 - Advisory published (delay was to coordinate fixes in upstream frameworks, Koa and Express)",
          "Severity": "HIGH",
          "References": [
            "https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS"
          ]
        },
        {
          "VulnerabilityID": "CVE-2014-10064",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "1.0.0",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-10064",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "The qs module before 1.0.0 does not have an option or default for spec ...",
          "Description": "The qs module before 1.0.0 does not have an option or default for specifying object depth and when parsing a string representing a deeply nested object will block the event loop for long periods of time. An attacker could leverage this to cause a temporary denial-of-service condition, for example, in a web application, other requests would not be processed while this blocking is occurring.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            }
          },
          "References": [
            "https://github.com/advisories/GHSA-f9cm-p3w6-xvr3",
            "https://nodesecurity.io/advisories/28",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-10064",
            "https://www.npmjs.com/advisories/28"
          ],
          "PublishedDate": "2018-05-31T20:29:00Z",
          "LastModifiedDate": "2019-10-09T23:09:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-7191",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "\u003e= 1.x",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-7191",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-qs: Denial-of-Service Memory Exhaustion",
          "Description": "The qs module before 1.0.0 in Node.js does not call the compact function for array data, which allows remote attackers to cause a denial of service (memory consumption) by using a large index value to create a sparse array.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://secunia.com/advisories/60026",
            "http://secunia.com/advisories/62170",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21685987",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687263",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687928",
            "https://access.redhat.com/errata/RHSA-2016:1380",
            "https://access.redhat.com/security/cve/CVE-2014-7191",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/96729",
            "https://github.com/advisories/GHSA-jjv7-qpx3-h62q",
            "https://github.com/raymondfeng/node-querystring/commit/43a604b7847e56bba49d0ce3e222fe89569354d8",
            "https://github.com/visionmedia/node-querystring/issues/104",
            "https://nodesecurity.io/advisories/qs_dos_memory_exhaustion",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-7191",
            "https://www.npmjs.com/advisories/29"
          ],
          "PublishedDate": "2014-10-19T01:55:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2017-1000048",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "6.3.2, 6.2.3, 6.1.2, 6.0.4",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2017-1000048",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Npm",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm"
          },
          "Title": "nodejs-qs: Prototype override protection bypass",
          "Description": "the web framework using ljharb's qs module older than v6.3.2, v6.2.3, v6.1.2, and v6.0.4 is vulnerable to a DoS. A malicious user can send a evil request to cause the web framework crash.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHSA-2017:2672",
            "https://access.redhat.com/security/cve/CVE-2017-1000048",
            "https://github.com/advisories/GHSA-gqgv-6jq5-jjj9",
            "https://github.com/ljharb/qs/commit/beade029171b8cef9cee0d03ebe577e2dd84976d",
            "https://github.com/ljharb/qs/issues/200",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-1000048",
            "https://snyk.io/vuln/npm:qs:20170213",
            "https://www.npmjs.com/advisories/1469"
          ],
          "PublishedDate": "2017-07-17T13:18:00Z",
          "LastModifiedDate": "2017-12-31T02:29:00Z"
        },
        {
          "VulnerabilityID": "NSWG-ECO-28",
          "PkgName": "qs",
          "InstalledVersion": "0.6.6",
          "FixedVersion": "\u003e= 1.x",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "Denial-of-Service Extended Event Loop Blocking",
          "Description": "The qs module does not have an option or default for specifying object depth and when parsing a string representing a deeply nested object will block the event loop for long periods of time. An attacker could leverage this to cause a temporary denial-of-service condition, for example, in a web application, other requests would not be processed while this blocking is occurring.",
          "Severity": "MEDIUM"
        },
        {
          "VulnerabilityID": "CVE-2014-6394",
          "PkgName": "send",
          "InstalledVersion": "0.1.4",
          "FixedVersion": "\u003e= 0.8.4",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-6394",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-send: directory traversal vulnerability",
          "Description": "visionmedia send before 0.8.4 for Node.js uses a partial comparison for verifying whether a directory is within the document root, which allows remote attackers to access restricted directories, as demonstrated using \"public-restricted\" under a \"public\" directory.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-22"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V2Score": 7.5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
              "V2Score": 2.6
            }
          },
          "References": [
            "http://lists.apple.com/archives/security-announce/2015/Sep/msg00002.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/139938.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/140020.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-September/139415.html",
            "http://secunia.com/advisories/62170",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687263",
            "http://www.openwall.com/lists/oss-security/2014/09/24/1",
            "http://www.openwall.com/lists/oss-security/2014/09/30/10",
            "http://www.securityfocus.com/bid/70100",
            "https://access.redhat.com/security/cve/CVE-2014-6394",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1146063",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6394",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/96727",
            "https://github.com/advisories/GHSA-xwg4-93c6-3h42",
            "https://github.com/visionmedia/send/commit/9c6ca9b2c0b880afd3ff91ce0d211213c5fa5f9a",
            "https://github.com/visionmedia/send/pull/59",
            "https://nodesecurity.io/advisories/send-directory-traversal",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6394",
            "https://support.apple.com/HT205217",
            "https://www.npmjs.com/advisories/32"
          ],
          "PublishedDate": "2014-10-08T17:55:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-8859",
          "PkgName": "send",
          "InstalledVersion": "0.1.4",
          "FixedVersion": "\u003e=0.11.1",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-8859",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "The send package before 0.11.1 for Node.js allows attackers to obtain  ...",
          "Description": "The send package before 0.11.1 for Node.js allows attackers to obtain the root path via unspecified vectors.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2016/04/20/11",
            "http://www.securityfocus.com/bid/96435",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8859",
            "https://github.com/advisories/GHSA-jgqf-hwc5-hh37",
            "https://github.com/expressjs/serve-static/blob/master/HISTORY.md#181--2015-01-20",
            "https://github.com/pillarjs/send/pull/70",
            "https://nodesecurity.io/advisories/56",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-8859",
            "https://www.npmjs.com/advisories/56"
          ],
          "PublishedDate": "2017-01-23T21:59:00Z",
          "LastModifiedDate": "2017-03-02T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-6394",
          "PkgName": "send",
          "InstalledVersion": "0.2.0",
          "FixedVersion": "\u003e= 0.8.4",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-6394",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "nodejs-send: directory traversal vulnerability",
          "Description": "visionmedia send before 0.8.4 for Node.js uses a partial comparison for verifying whether a directory is within the document root, which allows remote attackers to access restricted directories, as demonstrated using \"public-restricted\" under a \"public\" directory.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-22"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V2Score": 7.5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
              "V2Score": 2.6
            }
          },
          "References": [
            "http://lists.apple.com/archives/security-announce/2015/Sep/msg00002.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/139938.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-October/140020.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2014-September/139415.html",
            "http://secunia.com/advisories/62170",
            "http://www-01.ibm.com/support/docview.wss?uid=swg21687263",
            "http://www.openwall.com/lists/oss-security/2014/09/24/1",
            "http://www.openwall.com/lists/oss-security/2014/09/30/10",
            "http://www.securityfocus.com/bid/70100",
            "https://access.redhat.com/security/cve/CVE-2014-6394",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1146063",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6394",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/96727",
            "https://github.com/advisories/GHSA-xwg4-93c6-3h42",
            "https://github.com/visionmedia/send/commit/9c6ca9b2c0b880afd3ff91ce0d211213c5fa5f9a",
            "https://github.com/visionmedia/send/pull/59",
            "https://nodesecurity.io/advisories/send-directory-traversal",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6394",
            "https://support.apple.com/HT205217",
            "https://www.npmjs.com/advisories/32"
          ],
          "PublishedDate": "2014-10-08T17:55:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-8859",
          "PkgName": "send",
          "InstalledVersion": "0.2.0",
          "FixedVersion": "\u003e=0.11.1",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-8859",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "The send package before 0.11.1 for Node.js allows attackers to obtain  ...",
          "Description": "The send package before 0.11.1 for Node.js allows attackers to obtain the root path via unspecified vectors.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 5,
              "V3Score": 5.3
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2016/04/20/11",
            "http://www.securityfocus.com/bid/96435",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8859",
            "https://github.com/advisories/GHSA-jgqf-hwc5-hh37",
            "https://github.com/expressjs/serve-static/blob/master/HISTORY.md#181--2015-01-20",
            "https://github.com/pillarjs/send/pull/70",
            "https://nodesecurity.io/advisories/56",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-8859",
            "https://www.npmjs.com/advisories/56"
          ],
          "PublishedDate": "2017-01-23T21:59:00Z",
          "LastModifiedDate": "2017-03-02T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-1164",
          "PkgName": "serve-static",
          "InstalledVersion": "1.0.1",
          "FixedVersion": "~1.6.5, \u003e=1.7.2",
          "Layer": {},
          "SeveritySource": "nodejs-security-wg",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-1164",
          "DataSource": {
            "ID": "nodejs-security-wg",
            "Name": "Node.js Ecosystem Security Working Group",
            "URL": "https://github.com/nodejs/security-wg"
          },
          "Title": "Open redirect vulnerability in the serve-static plugin before 1.7.2 fo ...",
          "Description": "Open redirect vulnerability in the serve-static plugin before 1.7.2 for Node.js, when mounted at the root, allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a // (slash slash) followed by a domain in the PATH_INFO to the default URI.",
          "Severity": "MEDIUM",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://nodesecurity.io/advisories/serve-static-open-redirect",
            "http://www.securityfocus.com/bid/72064",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1181917",
            "https://exchange.xforce.ibmcloud.com/vulnerabilities/99936",
            "https://github.com/advisories/GHSA-c3x7-gjmx-r2ff",
            "https://github.com/expressjs/serve-static/issues/26",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-1164",
            "https://snyk.io/vuln/npm:serve-static:20150113",
            "https://www.npmjs.com/advisories/35",
            "https://www.owasp.org/index.php/Open_redirect"
          ],
          "PublishedDate": "2015-01-21T15:28:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/kotlin/example1/pom.xml",
      "Class": "lang-pkgs",
      "Type": "pom"
    },
    {
      "Target": "../../../../../../../examples/python/example2/requirements.txt",
      "Class": "lang-pkgs",
      "Type": "pip",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2019-19844",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.11.27, 2.2.9",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-19844",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: crafted email address allows account takeover",
          "Description": "Django before 1.11.27, 2.x before 2.2.9, and 3.x before 3.0.1 allows account takeover. A suitably crafted email address (that is equal to an existing user's email address after case transformation of Unicode characters) would allow an attacker to be sent a password reset token for the matched user account. (One mitigation in the new releases is to send password reset tokens only to the registered user email address.)",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-640"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 5,
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            }
          },
          "References": [
            "http://packetstormsecurity.com/files/155872/Django-Account-Hijack.html",
            "https://access.redhat.com/security/cve/CVE-2019-19844",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-19844",
            "https://docs.djangoproject.com/en/dev/releases/security/",
            "https://github.com/advisories/GHSA-vfq6-hq5r-27r6",
            "https://github.com/django/django/commit/5b1fbcef7a8bec991ebe7b2a18b5d5a95d72cb70",
            "https://github.com/django/django/commit/f4cff43bf921fcea6a29b726eb66767f67753fa2",
            "https://groups.google.com/forum/#!topic/django-announce/3oaB2rVH3a0",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HCM2DPUI7TOZWN4A6JFQFUVQ2XGE7GUD/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-19844",
            "https://seclists.org/bugtraq/2020/Jan/9",
            "https://security.gentoo.org/glsa/202004-17",
            "https://security.netapp.com/advisory/ntap-20200110-0003/",
            "https://ubuntu.com/security/notices/USN-4224-1",
            "https://usn.ubuntu.com/4224-1/",
            "https://www.debian.org/security/2020/dsa-4598",
            "https://www.djangoproject.com/weblog/2019/dec/18/security-releases/"
          ],
          "PublishedDate": "2019-12-18T19:15:00Z",
          "LastModifiedDate": "2020-01-08T04:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0474",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.11, 1.5.6, 1.6.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0474",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: MySQL typecasting",
          "Description": "The (1) FilePathField, (2) GenericIPAddressField, and (3) IPAddressField model field classes in Django before 1.4.11, 1.5.x before 1.5.6, 1.6.x before 1.6.3, and 1.7.x before 1.7 beta 2 do not properly perform type conversion, which allows remote attackers to have unspecified impact and vectors, related to \"MySQL typecasting.\"",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
              "V2Score": 10
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html",
            "http://rhn.redhat.com/errata/RHSA-2014-0456.html",
            "http://rhn.redhat.com/errata/RHSA-2014-0457.html",
            "http://secunia.com/advisories/61281",
            "http://www.debian.org/security/2014/dsa-2934",
            "http://www.ubuntu.com/usn/USN-2169-1",
            "https://access.redhat.com/security/cve/CVE-2014-0474",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0474",
            "https://ubuntu.com/security/notices/USN-2169-1",
            "https://www.djangoproject.com/weblog/2014/apr/21/security/"
          ],
          "PublishedDate": "2014-04-23T15:55:00Z",
          "LastModifiedDate": "2017-01-07T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-5143",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.21, 1.7.9, 1.8.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-5143",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: possible DoS by filling session store",
          "Description": "The session backends in Django before 1.4.21, 1.5.x through 1.6.x, 1.7.x before 1.7.9, and 1.8.x before 1.8.3 allows remote attackers to cause a denial of service (session store consumption) via multiple requests with unique session keys.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
              "V2Score": 7.8
            },
            "redhat": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            }
          },
          "References": [
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-November/172084.html",
            "http://lists.opensuse.org/opensuse-updates/2015-10/msg00043.html",
            "http://lists.opensuse.org/opensuse-updates/2015-10/msg00046.html",
            "http://rhn.redhat.com/errata/RHSA-2015-1678.html",
            "http://rhn.redhat.com/errata/RHSA-2015-1686.html",
            "http://www.debian.org/security/2015/dsa-3305",
            "http://www.oracle.com/technetwork/topics/security/bulletinoct2015-2511968.html",
            "http://www.securityfocus.com/bid/75666",
            "http://www.securitytracker.com/id/1032820",
            "http://www.ubuntu.com/usn/USN-2671-1",
            "https://access.redhat.com/security/cve/CVE-2015-5143",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5143",
            "https://github.com/advisories/GHSA-h582-2pch-3xv3",
            "https://nvd.nist.gov/vuln/detail/CVE-2015-5143",
            "https://security.gentoo.org/glsa/201510-06",
            "https://ubuntu.com/security/notices/USN-2671-1",
            "https://www.djangoproject.com/weblog/2015/jul/08/security-releases/"
          ],
          "PublishedDate": "2015-07-14T17:59:00Z",
          "LastModifiedDate": "2017-09-22T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-2512",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.8.10, 1.9.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-2512",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: Malicious redirect and possible XSS attack via user-supplied redirect URLs containing basic auth",
          "Description": "The utils.http.is_safe_url function in Django before 1.8.10 and 1.9.x before 1.9.3 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks or possibly conduct cross-site scripting (XSS) attacks via a URL containing basic authentication, as demonstrated by http://mysite.example.com\\@attacker.com.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N",
              "V2Score": 4.3,
              "V3Score": 7.4
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 5.8
            }
          },
          "References": [
            "http://rhn.redhat.com/errata/RHSA-2016-0502.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0504.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0505.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0506.html",
            "http://www.debian.org/security/2016/dsa-3544",
            "http://www.oracle.com/technetwork/topics/security/bulletinapr2016-2952098.html",
            "http://www.securityfocus.com/bid/83879",
            "http://www.securitytracker.com/id/1035152",
            "http://www.ubuntu.com/usn/USN-2915-1",
            "http://www.ubuntu.com/usn/USN-2915-2",
            "http://www.ubuntu.com/usn/USN-2915-3",
            "https://access.redhat.com/security/cve/CVE-2016-2512",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2512",
            "https://github.com/django/django/commit/c5544d289233f501917e25970c03ed444abbd4f0",
            "https://ubuntu.com/security/notices/USN-2915-1",
            "https://www.djangoproject.com/weblog/2016/mar/01/security-releases/"
          ],
          "PublishedDate": "2016-04-08T15:59:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-7401",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.8.15, 1.9.10",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-7401",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: CSRF protection bypass on a site with Google Analytics",
          "Description": "The cookie parsing code in Django before 1.8.15 and 1.9.x before 1.9.10, when used on a site with Google Analytics, allows remote attackers to bypass an intended CSRF protection mechanism by setting arbitrary cookies.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-254"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 6.1
            }
          },
          "References": [
            "http://rhn.redhat.com/errata/RHSA-2016-2038.html",
            "http://rhn.redhat.com/errata/RHSA-2016-2039.html",
            "http://rhn.redhat.com/errata/RHSA-2016-2040.html",
            "http://rhn.redhat.com/errata/RHSA-2016-2041.html",
            "http://rhn.redhat.com/errata/RHSA-2016-2042.html",
            "http://rhn.redhat.com/errata/RHSA-2016-2043.html",
            "http://www.debian.org/security/2016/dsa-3678",
            "http://www.securityfocus.com/bid/93182",
            "http://www.securitytracker.com/id/1036899",
            "http://www.ubuntu.com/usn/USN-3089-1",
            "https://access.redhat.com/security/cve/CVE-2016-7401",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-7401",
            "https://ubuntu.com/security/notices/USN-3089-1",
            "https://www.djangoproject.com/weblog/2016/sep/26/security-releases/"
          ],
          "PublishedDate": "2016-10-03T18:59:00Z",
          "LastModifiedDate": "2018-01-05T02:31:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-9014",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.8.16, 1.9.11, 1.10.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-9014",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: DNS rebinding vulnerability when 'DEBUG=True'",
          "Description": "Django before 1.8.x before 1.8.16, 1.9.x before 1.9.11, and 1.10.x before 1.10.3, when settings.DEBUG is True, allow remote attackers to conduct DNS rebinding attacks by leveraging failure to validate the HTTP Host header against settings.ALLOWED_HOSTS.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-264"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.1
            },
            "redhat": {
              "V2Vector": "AV:N/AC:H/Au:N/C:P/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
              "V2Score": 4,
              "V3Score": 7.4
            }
          },
          "References": [
            "http://www.debian.org/security/2017/dsa-3835",
            "http://www.securityfocus.com/bid/94068",
            "http://www.securitytracker.com/id/1037159",
            "http://www.ubuntu.com/usn/USN-3115-1",
            "https://access.redhat.com/security/cve/CVE-2016-9014",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-9014",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/OG5ROMUPS6C7BXELD3TAUUH7OBYV56WQ/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QXDKJYHN74BWY3P7AR2UZDVJREQMRE6S/",
            "https://ubuntu.com/security/notices/USN-3115-1",
            "https://www.djangoproject.com/weblog/2016/nov/01/security-releases/"
          ],
          "PublishedDate": "2016-12-09T20:59:00Z",
          "LastModifiedDate": "2017-11-04T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0472",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.11, 1.5.6, 1.6.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0472",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: unexpected code execution using reverse()",
          "Description": "The django.core.urlresolvers.reverse function in Django before 1.4.11, 1.5.x before 1.5.6, 1.6.x before 1.6.3, and 1.7.x before 1.7 beta 2 allows remote attackers to import and execute arbitrary Python modules by leveraging a view that constructs URLs using user input and a \"dotted Python path.\"",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-94"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:H/Au:N/C:P/I:P/A:P",
              "V2Score": 5.1
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html",
            "http://rhn.redhat.com/errata/RHSA-2014-0456.html",
            "http://rhn.redhat.com/errata/RHSA-2014-0457.html",
            "http://secunia.com/advisories/61281",
            "http://www.debian.org/security/2014/dsa-2934",
            "http://www.ubuntu.com/usn/USN-2169-1",
            "https://access.redhat.com/security/cve/CVE-2014-0472",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0472",
            "https://ubuntu.com/security/notices/USN-2169-1",
            "https://www.djangoproject.com/weblog/2014/apr/21/security/"
          ],
          "PublishedDate": "2014-04-23T15:55:00Z",
          "LastModifiedDate": "2017-01-07T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0473",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.11, 1.5.6, 1.6.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0473",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: caching of anonymous pages could reveal CSRF token",
          "Description": "The caching framework in Django before 1.4.11, 1.5.x before 1.5.6, 1.6.x before 1.6.3, and 1.7.x before 1.7 beta 2 reuses a cached CSRF token for all anonymous users, which allows remote attackers to bypass CSRF protections by reading the CSRF cookie for anonymous users.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-264"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V2Score": 5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html",
            "http://rhn.redhat.com/errata/RHSA-2014-0456.html",
            "http://rhn.redhat.com/errata/RHSA-2014-0457.html",
            "http://secunia.com/advisories/61281",
            "http://www.debian.org/security/2014/dsa-2934",
            "http://www.ubuntu.com/usn/USN-2169-1",
            "https://access.redhat.com/security/cve/CVE-2014-0473",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0473",
            "https://ubuntu.com/security/notices/USN-2169-1",
            "https://www.djangoproject.com/weblog/2014/apr/21/security/"
          ],
          "PublishedDate": "2014-04-23T15:55:00Z",
          "LastModifiedDate": "2017-01-07T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0480",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.14, 1.5.9, 1.6.6",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0480",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: reverse() can generate URLs pointing to other hosts, leading to phishing attacks",
          "Description": "The core.urlresolvers.reverse function in Django before 1.4.14, 1.5.x before 1.5.9, 1.6.x before 1.6.6, and 1.7 before release candidate 3 does not properly validate URLs, which allows remote attackers to conduct phishing attacks via a // (slash slash) in a URL, which triggers a scheme-relative URL to be generated.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 5.8
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html",
            "http://secunia.com/advisories/59782",
            "http://secunia.com/advisories/61276",
            "http://secunia.com/advisories/61281",
            "http://www.debian.org/security/2014/dsa-3010",
            "http://www.securityfocus.com/bid/69425",
            "https://access.redhat.com/security/cve/CVE-2014-0480",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0480",
            "https://ubuntu.com/security/notices/USN-2347-1",
            "https://www.djangoproject.com/weblog/2014/aug/20/security/"
          ],
          "PublishedDate": "2014-08-26T14:55:00Z",
          "LastModifiedDate": "2018-10-30T16:27:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0481",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.14, 1.5.9, 1.6.6",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0481",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: file upload denial of service",
          "Description": "The default configuration for the file upload handling system in Django before 1.4.14, 1.5.x before 1.5.9, 1.6.x before 1.6.6, and 1.7 before release candidate 3 uses a sequential file name generation process when a file with a conflicting name is uploaded, which allows remote attackers to cause a denial of service (CPU consumption) by unloading a multiple files with the same name.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V2Score": 4.3
            },
            "redhat": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html",
            "http://secunia.com/advisories/59782",
            "http://secunia.com/advisories/61276",
            "http://secunia.com/advisories/61281",
            "http://www.debian.org/security/2014/dsa-3010",
            "https://access.redhat.com/security/cve/CVE-2014-0481",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0481",
            "https://ubuntu.com/security/notices/USN-2347-1",
            "https://www.djangoproject.com/weblog/2014/aug/20/security/"
          ],
          "PublishedDate": "2014-08-26T14:55:00Z",
          "LastModifiedDate": "2018-10-30T16:27:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0482",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.14, 1.5.9, 1.6.6",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0482",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: RemoteUserMiddleware session hijacking",
          "Description": "The contrib.auth.middleware.RemoteUserMiddleware middleware in Django before 1.4.14, 1.5.x before 1.5.9, 1.6.x before 1.6.6, and 1.7 before release candidate 3, when using the contrib.auth.backends.RemoteUserBackend backend, allows remote authenticated users to hijack web sessions via vectors related to the REMOTE_USER header.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-287"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:S/C:P/I:P/A:P",
              "V2Score": 6
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 5.8
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html",
            "http://secunia.com/advisories/59782",
            "http://secunia.com/advisories/61276",
            "http://secunia.com/advisories/61281",
            "http://www.debian.org/security/2014/dsa-3010",
            "https://access.redhat.com/security/cve/CVE-2014-0482",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0482",
            "https://ubuntu.com/security/notices/USN-2347-1",
            "https://www.djangoproject.com/weblog/2014/aug/20/security/"
          ],
          "PublishedDate": "2014-08-26T14:55:00Z",
          "LastModifiedDate": "2018-10-30T16:27:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-0219",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.18, 1.6.10, 1.7.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-0219",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: WSGI header spoofing via underscore/dash conflation",
          "Description": "Django before 1.4.18, 1.6.x before 1.6.10, and 1.7.x before 1.7.3 allows remote attackers to spoof WSGI headers by using an _ (underscore) character instead of a - (dash) character in an HTTP header, as demonstrated by an X-Auth_User header.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-17"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V2Score": 5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
              "V2Score": 5.8
            }
          },
          "References": [
            "http://advisories.mageia.org/MGASA-2015-0026.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148485.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148608.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148696.html",
            "http://lists.opensuse.org/opensuse-updates/2015-04/msg00001.html",
            "http://lists.opensuse.org/opensuse-updates/2015-09/msg00035.html",
            "http://secunia.com/advisories/62285",
            "http://secunia.com/advisories/62309",
            "http://secunia.com/advisories/62718",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:036",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:109",
            "http://www.ubuntu.com/usn/USN-2469-1",
            "https://access.redhat.com/security/cve/CVE-2015-0219",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0219",
            "https://ubuntu.com/security/notices/USN-2469-1",
            "https://www.djangoproject.com/weblog/2015/jan/13/security/"
          ],
          "PublishedDate": "2015-01-16T16:59:00Z",
          "LastModifiedDate": "2016-12-22T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-0220",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.18, 1.6.10, 1.7.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-0220",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: Mitigated possible XSS attack via user-supplied redirect URLs",
          "Description": "The django.util.http.is_safe_url function in Django before 1.4.18, 1.6.x before 1.6.10, and 1.7.x before 1.7.3 does not properly handle leading whitespaces, which allows remote attackers to conduct cross-site scripting (XSS) attacks via a crafted URL, related to redirect URLs, as demonstrated by a \"\\njavascript:\" URL.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://advisories.mageia.org/MGASA-2015-0026.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148485.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148608.html",
            "http://lists.opensuse.org/opensuse-updates/2015-04/msg00001.html",
            "http://lists.opensuse.org/opensuse-updates/2015-09/msg00035.html",
            "http://secunia.com/advisories/62285",
            "http://secunia.com/advisories/62309",
            "http://secunia.com/advisories/62718",
            "http://ubuntu.com/usn/usn-2469-1",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:036",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:109",
            "https://access.redhat.com/security/cve/CVE-2015-0220",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0220",
            "https://ubuntu.com/security/notices/USN-2469-1",
            "https://www.djangoproject.com/weblog/2015/jan/13/security/"
          ],
          "PublishedDate": "2015-01-16T16:59:00Z",
          "LastModifiedDate": "2016-12-22T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-0221",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.18, 1.6.10, 1.7.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-0221",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: denial of service attack against django.views.static.serve",
          "Description": "The django.views.static.serve view in Django before 1.4.18, 1.6.x before 1.6.10, and 1.7.x before 1.7.3 reads files an entire line at a time, which allows remote attackers to cause a denial of service (memory consumption) via a long line in a file.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-399"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://advisories.mageia.org/MGASA-2015-0026.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148485.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148608.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148696.html",
            "http://lists.opensuse.org/opensuse-updates/2015-04/msg00001.html",
            "http://lists.opensuse.org/opensuse-updates/2015-09/msg00035.html",
            "http://secunia.com/advisories/62285",
            "http://secunia.com/advisories/62309",
            "http://secunia.com/advisories/62718",
            "http://ubuntu.com/usn/usn-2469-1",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:036",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:109",
            "https://access.redhat.com/security/cve/CVE-2015-0221",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0221",
            "https://ubuntu.com/security/notices/USN-2469-1",
            "https://www.djangoproject.com/weblog/2015/jan/13/security/"
          ],
          "PublishedDate": "2015-01-16T16:59:00Z",
          "LastModifiedDate": "2016-12-22T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-0222",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.18, 1.6.10, 1.7.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-0222",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: database denial of service with ModelMultipleChoiceField",
          "Description": "ModelMultipleChoiceField in Django 1.6.x before 1.6.10 and 1.7.x before 1.7.3, when show_hidden_initial is set to True, allows remote attackers to cause a denial of service by submitting duplicate values, which triggers a large number of SQL queries.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-17"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V2Score": 5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:P",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://advisories.mageia.org/MGASA-2015-0026.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148485.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148608.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-January/148696.html",
            "http://lists.opensuse.org/opensuse-updates/2015-04/msg00001.html",
            "http://lists.opensuse.org/opensuse-updates/2015-09/msg00035.html",
            "http://secunia.com/advisories/62285",
            "http://secunia.com/advisories/62309",
            "http://ubuntu.com/usn/usn-2469-1",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:109",
            "https://access.redhat.com/security/cve/CVE-2015-0222",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0222",
            "https://ubuntu.com/security/notices/USN-2469-1",
            "https://www.djangoproject.com/weblog/2015/jan/13/security/"
          ],
          "PublishedDate": "2015-01-16T16:59:00Z",
          "LastModifiedDate": "2016-12-22T02:59:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-2241",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.7.6, 1.8b2",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-2241",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: XSS attack via properties in ModelAdmin.readonly_fields",
          "Description": "Cross-site scripting (XSS) vulnerability in the contents function in admin/helpers.py in Django before 1.7.6 and 1.8 before 1.8b2 allows remote attackers to inject arbitrary web script or HTML via a model attribute in ModelAdmin.readonly_fields, as demonstrated by a @property.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:109",
            "http://www.securityfocus.com/bid/73095",
            "https://access.redhat.com/security/cve/CVE-2015-2241",
            "https://code.djangoproject.com/ticket/24461",
            "https://www.djangoproject.com/weblog/2015/mar/09/security-releases/"
          ],
          "PublishedDate": "2015-03-12T14:59:00Z",
          "LastModifiedDate": "2016-12-03T03:04:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-2317",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.20, 1.6.11, 1.7.7, 1.8c1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-2317",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: possible XSS attack via user-supplied redirect URLs",
          "Description": "The utils.http.is_safe_url function in Django before 1.4.20, 1.5.x, 1.6.x before 1.6.11, 1.7.x before 1.7.7, and 1.8.x before 1.8c1 does not properly validate URLs, which allows remote attackers to conduct cross-site scripting (XSS) attacks via a control character in a URL, as demonstrated by a \\x08javascript: URL.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            },
            "redhat": {
              "V2Vector": "AV:N/AC:H/Au:N/C:N/I:P/A:N",
              "V2Score": 2.6
            }
          },
          "References": [
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-April/155421.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-June/160263.html",
            "http://lists.opensuse.org/opensuse-updates/2015-04/msg00001.html",
            "http://lists.opensuse.org/opensuse-updates/2015-09/msg00035.html",
            "http://ubuntu.com/usn/usn-2539-1",
            "http://www.debian.org/security/2015/dsa-3204",
            "http://www.mandriva.com/security/advisories?name=MDVSA-2015:195",
            "http://www.oracle.com/technetwork/topics/security/bulletinapr2015-2511959.html",
            "http://www.securityfocus.com/bid/73319",
            "https://access.redhat.com/security/cve/CVE-2015-2317",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2317",
            "https://ubuntu.com/security/notices/USN-2539-1",
            "https://www.djangoproject.com/weblog/2015/mar/18/security-releases/"
          ],
          "PublishedDate": "2015-03-25T14:59:00Z",
          "LastModifiedDate": "2018-10-30T16:27:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-5144",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.21, 1.7.9, 1.8.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-5144",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: possible header injection due to validators accepting newlines in input",
          "Description": "Django before 1.4.21, 1.5.x through 1.6.x, 1.7.x before 1.7.9, and 1.8.x before 1.8.3 uses an incorrect regular expression, which allows remote attackers to inject arbitrary headers and conduct HTTP response splitting attacks via a newline character in an (1) email message to the EmailValidator, a (2) URL to the URLValidator, or unspecified vectors to the (3) validate_ipv4_address or (4) validate_slug validator.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-November/172084.html",
            "http://lists.opensuse.org/opensuse-updates/2015-10/msg00043.html",
            "http://lists.opensuse.org/opensuse-updates/2015-10/msg00046.html",
            "http://www.debian.org/security/2015/dsa-3305",
            "http://www.oracle.com/technetwork/topics/security/bulletinoct2015-2511968.html",
            "http://www.securityfocus.com/bid/75665",
            "http://www.securitytracker.com/id/1032820",
            "http://www.ubuntu.com/usn/USN-2671-1",
            "https://access.redhat.com/security/cve/CVE-2015-5144",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5144",
            "https://security.gentoo.org/glsa/201510-06",
            "https://ubuntu.com/security/notices/USN-2671-1",
            "https://www.djangoproject.com/weblog/2015/jul/08/security-releases/"
          ],
          "PublishedDate": "2015-07-14T17:59:00Z",
          "LastModifiedDate": "2017-09-22T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2015-8213",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.7.11, 1.8.7, 1.9rc2",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2015-8213",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: Information leak through date template filter",
          "Description": "The get_format function in utils/formats.py in Django before 1.7.x before 1.7.11, 1.8.x before 1.8.7, and 1.9.x before 1.9rc2 might allow remote attackers to obtain sensitive application secrets via a settings key in place of a date/time format setting, as demonstrated by SECRET_KEY.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-200"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V2Score": 5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-December/173375.html",
            "http://lists.fedoraproject.org/pipermail/package-announce/2015-December/174770.html",
            "http://lists.opensuse.org/opensuse-updates/2015-12/msg00014.html",
            "http://lists.opensuse.org/opensuse-updates/2015-12/msg00017.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0129.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0156.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0157.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0158.html",
            "http://www.debian.org/security/2015/dsa-3404",
            "http://www.securityfocus.com/bid/77750",
            "http://www.securitytracker.com/id/1034237",
            "http://www.ubuntu.com/usn/USN-2816-1",
            "https://access.redhat.com/security/cve/CVE-2015-8213",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-8213",
            "https://github.com/django/django/commit/316bc3fc9437c5960c24baceb93c73f1939711e4",
            "https://ubuntu.com/security/notices/USN-2816-1",
            "https://www.djangoproject.com/weblog/2015/nov/24/security-releases-issued/"
          ],
          "PublishedDate": "2015-12-07T20:59:00Z",
          "LastModifiedDate": "2016-12-07T18:26:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-6186",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.8.14, 1.9.8, 1.10rc1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-6186",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "django: XSS in admin's add/change related popup",
          "Description": "Cross-site scripting (XSS) vulnerability in the dismissChangeRelatedObjectPopup function in contrib/admin/static/admin/js/admin/RelatedObjectLookups.js in Django before 1.8.14, 1.9.x before 1.9.8, and 1.10.x before 1.10rc1 allows remote attackers to inject arbitrary web script or HTML via vectors involving unsafe usage of Element.innerHTML.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 6.1
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 6.1
            }
          },
          "References": [
            "http://packetstormsecurity.com/files/137965/Django-3.3.0-Script-Insertion.html",
            "http://rhn.redhat.com/errata/RHSA-2016-1594.html",
            "http://rhn.redhat.com/errata/RHSA-2016-1595.html",
            "http://rhn.redhat.com/errata/RHSA-2016-1596.html",
            "http://seclists.org/fulldisclosure/2016/Jul/53",
            "http://www.debian.org/security/2016/dsa-3622",
            "http://www.securityfocus.com/archive/1/538947/100/0/threaded",
            "http://www.securityfocus.com/bid/92058",
            "http://www.securitytracker.com/id/1036338",
            "http://www.ubuntu.com/usn/USN-3039-1",
            "http://www.vulnerability-lab.com/get_content.php?id=1869",
            "https://access.redhat.com/security/cve/CVE-2016-6186",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6186",
            "https://github.com/django/django/commit/d03bf6fe4e9bf5b07de62c1a271c4b41a7d3d158",
            "https://github.com/django/django/commit/f68e5a99164867ab0e071a936470958ed867479d",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DMLLFAUT4J4IP4P2KI4NOVWRMHA22WUJ/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KHHPN6MISX5I6UTXQHYLPTLEEUE6WDXW/",
            "https://ubuntu.com/security/notices/USN-3039-1",
            "https://www.djangoproject.com/weblog/2016/jul/18/security-releases/",
            "https://www.exploit-db.com/exploits/40129/"
          ],
          "PublishedDate": "2016-08-05T15:59:00Z",
          "LastModifiedDate": "2018-10-09T20:00:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-33203",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "2.2.24, 3.1.12, 3.2.4",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-33203",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "django: Potential directory traversal via 'admindocs'",
          "Description": "Django before 2.2.24, 3.x before 3.1.12, and 3.2.x before 3.2.4 has a potential directory traversal via django.contrib.admindocs. Staff members could use the TemplateDetailView view to check the existence of arbitrary files. Additionally, if (and only if) the default admindocs templates have been customized by application developers to also show file contents, then not only the existence but also the file contents would have been exposed. In other words, there is directory traversal outside of the template root directories.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-22"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 4,
              "V3Score": 4.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 4.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-33203",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33203",
            "https://docs.djangoproject.com/en/3.2/releases/security/",
            "https://github.com/advisories/GHSA-68w8-qjq3-2gfm",
            "https://github.com/django/django/commit/053cc9534d174dc89daba36724ed2dcb36755b90",
            "https://groups.google.com/forum/#!forum/django-announce",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-33203",
            "https://security.netapp.com/advisory/ntap-20210727-0004/",
            "https://ubuntu.com/security/notices/USN-4975-1",
            "https://ubuntu.com/security/notices/USN-4975-2",
            "https://www.djangoproject.com/weblog/2021/jun/02/security-releases/"
          ],
          "PublishedDate": "2021-06-08T18:15:00Z",
          "LastModifiedDate": "2022-02-25T18:42:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0483",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.4.14, 1.5.9, 1.6.6",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0483",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "Django: data leakage via querystring manipulation in admin",
          "Description": "The administrative interface (contrib.admin) in Django before 1.4.14, 1.5.x before 1.5.9, 1.6.x before 1.6.6, and 1.7 before release candidate 3 does not check if a field represents a relationship between models, which allows remote authenticated users to obtain sensitive information via a to_field parameter in a popup action to an admin change form page, as demonstrated by a /admin/auth/user/?pop=1\u0026t=password URI.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-264"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:S/C:P/I:N/A:N",
              "V2Score": 3.5
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:S/C:P/I:N/A:N",
              "V2Score": 3.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-updates/2014-09/msg00023.html",
            "http://secunia.com/advisories/59782",
            "http://secunia.com/advisories/61276",
            "http://secunia.com/advisories/61281",
            "http://www.debian.org/security/2014/dsa-3010",
            "https://access.redhat.com/security/cve/CVE-2014-0483",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0483",
            "https://github.com/django/django/commit/2b31342cdf14fc20e07c43d258f1e7334ad664a6",
            "https://ubuntu.com/security/notices/USN-2347-1",
            "https://www.djangoproject.com/weblog/2014/aug/20/security/"
          ],
          "PublishedDate": "2014-08-26T14:55:00Z",
          "LastModifiedDate": "2018-10-30T16:27:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-2513",
          "PkgName": "Django",
          "InstalledVersion": "1.3.10",
          "FixedVersion": "1.8.10, 1.9.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-2513",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-django: User enumeration through timing difference on password hasher work factor upgrade",
          "Description": "The password hasher in contrib/auth/hashers.py in Django before 1.8.10 and 1.9.x before 1.9.3 allows remote attackers to enumerate users via a timing attack involving login requests.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-200"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
              "V2Score": 2.6,
              "V3Score": 3.1
            },
            "redhat": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V2Score": 4.3
            }
          },
          "References": [
            "http://rhn.redhat.com/errata/RHSA-2016-0502.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0504.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0505.html",
            "http://rhn.redhat.com/errata/RHSA-2016-0506.html",
            "http://www.debian.org/security/2016/dsa-3544",
            "http://www.oracle.com/technetwork/topics/security/bulletinapr2016-2952098.html",
            "http://www.securityfocus.com/bid/83878",
            "http://www.securitytracker.com/id/1035152",
            "http://www.ubuntu.com/usn/USN-2915-1",
            "http://www.ubuntu.com/usn/USN-2915-2",
            "http://www.ubuntu.com/usn/USN-2915-3",
            "https://access.redhat.com/security/cve/CVE-2016-2513",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-2513",
            "https://github.com/django/django/commit/67b46ba7016da2d259c1ecc7d666d11f5e1cfaab",
            "https://ubuntu.com/security/notices/USN-2915-1",
            "https://www.djangoproject.com/weblog/2016/mar/01/security-releases/"
          ],
          "PublishedDate": "2016-04-08T15:59:00Z",
          "LastModifiedDate": "2017-09-08T01:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2018-1000656",
          "PkgName": "Flask",
          "InstalledVersion": "0.5.1",
          "FixedVersion": "0.12.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2018-1000656",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-flask: Denial of Service via crafted JSON file",
          "Description": "The Pallets Project flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3. NOTE: this may overlap CVE-2019-1010083.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2018-1000656",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000656",
            "https://github.com/advisories/GHSA-562c-5r94-xh97",
            "https://github.com/pallets/flask/pull/2691",
            "https://github.com/pallets/flask/releases/tag/0.12.3",
            "https://lists.debian.org/debian-lts-announce/2019/08/msg00025.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1000656",
            "https://security.netapp.com/advisory/ntap-20190221-0001/",
            "https://ubuntu.com/security/notices/USN-4378-1",
            "https://usn.ubuntu.com/4378-1/"
          ],
          "PublishedDate": "2018-08-20T19:31:00Z",
          "LastModifiedDate": "2020-06-09T22:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-1010083",
          "PkgName": "Flask",
          "InstalledVersion": "0.5.1",
          "FixedVersion": "1.0",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-1010083",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-flask: unexpected memory usage can lead to denial of service via crafted encoded JSON data",
          "Description": "The Pallets Project Flask before 1.0 is affected by: unexpected memory usage. The impact is: denial of service. The attack vector is: crafted encoded JSON data. The fixed version is: 1. NOTE: this may overlap CVE-2018-1000656.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-1010083",
            "https://github.com/advisories/GHSA-5wv5-4vpf-pj6m",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-1010083",
            "https://palletsprojects.com/blog/flask-1-0-released/",
            "https://snyk.io/vuln/SNYK-PYTHON-FLASK-451637",
            "https://www.palletsprojects.com/blog/flask-1-0-released/"
          ],
          "PublishedDate": "2019-07-17T14:15:00Z",
          "LastModifiedDate": "2020-08-24T17:37:00Z"
        },
        {
          "VulnerabilityID": "CVE-2016-10745",
          "PkgName": "Jinja2",
          "InstalledVersion": "2.7.2",
          "FixedVersion": "2.8.1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2016-10745",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-jinja2: Sandbox escape due to information disclosure via str.format",
          "Description": "In Pallets Jinja before 2.8.1, str.format allows a sandbox escape.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-134"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 8.6
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 9
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00030.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00064.html",
            "https://access.redhat.com/errata/RHSA-2019:1022",
            "https://access.redhat.com/errata/RHSA-2019:1237",
            "https://access.redhat.com/errata/RHSA-2019:1260",
            "https://access.redhat.com/errata/RHSA-2019:3964",
            "https://access.redhat.com/errata/RHSA-2019:4062",
            "https://access.redhat.com/security/cve/CVE-2016-10745",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10745",
            "https://github.com/advisories/GHSA-hj2j-77xm-mc5v",
            "https://github.com/pallets/jinja/commit/9b53045c34e61013dc8f09b7e52a555fa16bed16",
            "https://linux.oracle.com/cve/CVE-2016-10745.html",
            "https://linux.oracle.com/errata/ELSA-2019-1022.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2016-10745",
            "https://palletsprojects.com/blog/jinja-281-released/",
            "https://ubuntu.com/security/notices/USN-4011-1",
            "https://ubuntu.com/security/notices/USN-4011-2",
            "https://usn.ubuntu.com/4011-1/",
            "https://usn.ubuntu.com/4011-2/"
          ],
          "PublishedDate": "2019-04-08T13:29:00Z",
          "LastModifiedDate": "2019-06-06T16:29:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-10906",
          "PkgName": "Jinja2",
          "InstalledVersion": "2.7.2",
          "FixedVersion": "2.10.1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-10906",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-jinja2: str.format_map allows sandbox escape",
          "Description": "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 8.6
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
              "V3Score": 9
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00030.html",
            "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00064.html",
            "https://access.redhat.com/errata/RHSA-2019:1152",
            "https://access.redhat.com/errata/RHSA-2019:1237",
            "https://access.redhat.com/errata/RHSA-2019:1329",
            "https://access.redhat.com/security/cve/CVE-2019-10906",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10906",
            "https://github.com/advisories/GHSA-462w-v97r-4m45",
            "https://linux.oracle.com/cve/CVE-2019-10906.html",
            "https://linux.oracle.com/errata/ELSA-2019-1152.html",
            "https://lists.apache.org/thread.html/09fc842ff444cd43d9d4c510756fec625ef8eb1175f14fd21de2605f@%3Cdevnull.infra.apache.org%3E",
            "https://lists.apache.org/thread.html/2b52b9c8b9d6366a4f1b407a8bde6af28d9fc73fdb3b37695fd0d9ac@%3Cdevnull.infra.apache.org%3E",
            "https://lists.apache.org/thread.html/320441dccbd9a545320f5f07306d711d4bbd31ba43dc9eebcfc602df@%3Cdevnull.infra.apache.org%3E",
            "https://lists.apache.org/thread.html/46c055e173b52d599c648a98199972dbd6a89d2b4c4647b0500f2284@%3Cdevnull.infra.apache.org%3E",
            "https://lists.apache.org/thread.html/57673a78c4d5c870d3f21465c7e2946b9f8285c7c57e54c2ae552f02@%3Ccommits.airflow.apache.org%3E",
            "https://lists.apache.org/thread.html/7f39f01392d320dfb48e4901db68daeece62fd60ef20955966739993@%3Ccommits.airflow.apache.org%3E",
            "https://lists.apache.org/thread.html/b2380d147b508bbcb90d2cad443c159e63e12555966ab4f320ee22da@%3Ccommits.airflow.apache.org%3E",
            "https://lists.apache.org/thread.html/f0c4a03418bcfe70c539c5dbaf99c04c98da13bfa1d3266f08564316@%3Ccommits.airflow.apache.org%3E",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DSW3QZMFVVR7YE3UT4YRQA272TYAL5AF/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QCDYIS254EJMBNWOG4S5QY6AOTOR4TZU/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TS7IVZAJBWOHNRDMFJDIZVFCMRP6YIUQ/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-10906",
            "https://palletsprojects.com/blog/jinja-2-10-1-released",
            "https://palletsprojects.com/blog/jinja-2-10-1-released/",
            "https://ubuntu.com/security/notices/USN-4011-1",
            "https://ubuntu.com/security/notices/USN-4011-2",
            "https://usn.ubuntu.com/4011-1/",
            "https://usn.ubuntu.com/4011-2/"
          ],
          "PublishedDate": "2019-04-07T00:29:00Z",
          "LastModifiedDate": "2020-08-24T17:37:00Z"
        },
        {
          "VulnerabilityID": "CVE-2014-0012",
          "PkgName": "Jinja2",
          "InstalledVersion": "2.7.2",
          "FixedVersion": "2.7.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2014-0012",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-jinja2: FileSystemBytecodeCache insecure cache temporary file use, incorrect CVE-2014-1402 fix",
          "Description": "FileSystemBytecodeCache in Jinja2 2.7.2 does not properly create temporary directories, which allows local users to gain privileges by pre-creating a temporary directory with a user's uid.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-1402.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-264"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
              "V2Score": 4.4
            },
            "redhat": {
              "V2Vector": "AV:L/AC:M/Au:N/C:P/I:P/A:P",
              "V2Score": 4.4
            }
          },
          "References": [
            "http://seclists.org/oss-sec/2014/q1/73",
            "http://secunia.com/advisories/56328",
            "http://secunia.com/advisories/60738",
            "http://www.gentoo.org/security/en/glsa/glsa-201408-13.xml",
            "https://access.redhat.com/security/cve/CVE-2014-0012",
            "https://bugzilla.redhat.com/show_bug.cgi?id=1051421",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0012",
            "https://github.com/mitsuhiko/jinja2/commit/acb672b6a179567632e032f547582f30fa2f4aa7",
            "https://github.com/mitsuhiko/jinja2/pull/292",
            "https://github.com/mitsuhiko/jinja2/pull/296",
            "https://ubuntu.com/security/notices/USN-2301-1"
          ],
          "PublishedDate": "2014-05-19T14:55:00Z",
          "LastModifiedDate": "2015-12-14T23:07:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-28493",
          "PkgName": "Jinja2",
          "InstalledVersion": "2.7.2",
          "FixedVersion": "2.11.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-28493",
          "DataSource": {
            "ID": "osv",
            "Name": "Python Packaging Advisory Database",
            "URL": "https://github.com/pypa/advisory-db"
          },
          "Title": "python-jinja2: ReDoS vulnerability in the urlize filter",
          "Description": "This affects the package jinja2 from 0.0.0 and before 2.11.3. The ReDoS vulnerability is mainly due to the '_punctuation_re regex' operator and its use of multiple wildcards. The last wildcard is the most exploitable as it searches for trailing punctuation. This issue can be mitigated by Markdown to format user content instead of the urlize filter, or by implementing request timeouts and limiting process memory.",
          "Severity": "MEDIUM",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
              "V2Score": 5,
              "V3Score": 5.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-28493",
            "https://github.com/advisories/GHSA-g3rq-g295-4j3m",
            "https://github.com/pallets/jinja/blob/ab81fd9c277900c85da0c322a2ff9d68a235b2e6/src/jinja2/utils.py%23L20",
            "https://github.com/pallets/jinja/pull/1343",
            "https://linux.oracle.com/cve/CVE-2020-28493.html",
            "https://linux.oracle.com/errata/ELSA-2021-4162.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/PVAKCOO7VBVUBM3Q6CBBTPBFNP5NDXF4/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-28493",
            "https://snyk.io/vuln/SNYK-PYTHON-JINJA2-1012994"
          ],
          "PublishedDate": "2021-02-01T20:15:00Z",
          "LastModifiedDate": "2021-07-21T11:39:00Z"
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/ruby/example1/Gemfile.lock",
      "Class": "lang-pkgs",
      "Type": "bundler",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2020-8164",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.3, \u003e= 6.0.3.1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8164",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: possible strong parameters bypass",
          "Description": "A deserialization of untrusted data vulnerability exists in rails \u003c 5.2.4.3, rails \u003c 6.0.3.1 which can allow an attacker to supply information can be inadvertently leaked fromStrong Parameters.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-502"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00089.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00093.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00107.html",
            "https://access.redhat.com/security/cve/CVE-2020-8164",
            "https://github.com/advisories/GHSA-8727-m6gj-mc37",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/actionpack/CVE-2020-8164.yml",
            "https://groups.google.com/forum/#!topic/rubyonrails-security/f6ioe4sdpbY",
            "https://groups.google.com/g/rubyonrails-security/c/f6ioe4sdpbY",
            "https://hackerone.com/reports/292797",
            "https://lists.debian.org/debian-lts-announce/2020/06/msg00022.html",
            "https://lists.debian.org/debian-lts-announce/2020/07/msg00013.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8164",
            "https://weblog.rubyonrails.org/2020/5/18/Rails-5-2-4-3-and-6-0-3-1-have-been-released",
            "https://www.debian.org/security/2020/dsa-4766"
          ],
          "PublishedDate": "2020-06-19T17:15:00Z",
          "LastModifiedDate": "2020-09-30T18:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-22885",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4.6, ~\u003e 5.2.6, ~\u003e 6.0.3, \u003e= 6.0.3.7, \u003e= 6.1.3.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-22885",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: Possible Information Disclosure / Unintended Method Execution in Action Pack",
          "Description": "A possible information disclosure / unintended method execution vulnerability in Action Pack \u003e= 2.0.0 when using the 'redirect_to' or 'polymorphic_url'helper with untrusted user input.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-209"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-22885",
            "https://github.com/advisories/GHSA-hjg4-8q5f-x6fm",
            "https://github.com/rails/rails/releases/tag/v5.2.4.6",
            "https://github.com/rails/rails/releases/tag/v5.2.6",
            "https://github.com/rails/rails/releases/tag/v6.0.3.7",
            "https://github.com/rails/rails/releases/tag/v6.1.3.2",
            "https://groups.google.com/g/rubyonrails-security/c/NiQl-48cXYI",
            "https://hackerone.com/reports/1106652",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22885",
            "https://www.debian.org/security/2021/dsa-4929"
          ],
          "PublishedDate": "2021-05-27T12:15:00Z",
          "LastModifiedDate": "2021-08-05T12:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-22902",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 6.0.3, \u003e= 6.0.3.7, \u003e= 6.1.3.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-22902",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rails: Possible Denial of Service vulnerability in Action Dispatch",
          "Description": "The actionpack ruby gem (a framework for handling and responding to web requests in Rails) before 6.0.3.7, 6.1.3.2 suffers from a possible denial of service vulnerability in the Mime type parser of Action Dispatch. Carefully crafted Accept headers can cause the mime type parser in Action Dispatch to do catastrophic backtracking in the regular expression engine.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-22902",
            "https://discuss.rubyonrails.org/t/cve-2021-22902-possible-denial-of-service-vulnerability-in-action-dispatch/77866",
            "https://github.com/advisories/GHSA-g8ww-46x2-2p65",
            "https://github.com/rails/rails/releases/tag/v6.0.3.7",
            "https://github.com/rails/rails/releases/tag/v6.1.3.2",
            "https://groups.google.com/g/rubyonrails-security/c/_5ID_ld9u1c",
            "https://hackerone.com/reports/1138654",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22902"
          ],
          "PublishedDate": "2021-06-11T16:15:00Z",
          "LastModifiedDate": "2021-08-18T19:13:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-22904",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4.6, ~\u003e 5.2.6, ~\u003e 6.0.3, \u003e= 6.0.3.7, \u003e= 6.1.3.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-22904",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rails: Possible DoS Vulnerability in Action Controller Token Authentication",
          "Description": "The actionpack ruby gem before 6.1.3.2, 6.0.3.7, 5.2.4.6, 5.2.6 suffers from a possible denial of service vulnerability in the Token Authentication logic in Action Controller due to a too permissive regular expression. Impacted code uses 'authenticate_or_request_with_http_token' or 'authenticate_with_http_token' for request authentication.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-22904",
            "https://discuss.rubyonrails.org/t/cve-2021-22904-possible-dos-vulnerability-in-action-controller-token-authentication/77869",
            "https://github.com/advisories/GHSA-7wjx-3g7j-8584",
            "https://github.com/rails/rails/releases/tag/v5.2.4.6",
            "https://github.com/rails/rails/releases/tag/v5.2.6",
            "https://github.com/rails/rails/releases/tag/v6.0.3.7",
            "https://github.com/rails/rails/releases/tag/v6.1.3.2",
            "https://groups.google.com/g/rubyonrails-security/c/Pf1TjkOBdyQ",
            "https://hackerone.com/reports/1101125",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22904",
            "https://security.netapp.com/advisory/ntap-20210805-0009/"
          ],
          "PublishedDate": "2021-06-11T16:15:00Z",
          "LastModifiedDate": "2021-09-20T13:51:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-22942",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 6.0.4, \u003e= 6.0.4.1, \u003e= 6.1.4.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-22942",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: possible open redirect in the Host Authorization middleware",
          "Description": "A possible open redirect vulnerability in the Host Authorization middleware in Action Pack \u003e= 6.0.0 that could allow attackers to redirect users to a malicious website.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-601"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 5.8,
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
              "V3Score": 5.4
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2021/12/14/5",
            "https://access.redhat.com/security/cve/CVE-2021-22942",
            "https://access.redhat.com/security/cve/cve-2021-22942",
            "https://discuss.rubyonrails.org/t/cve-2021-22942-possible-open-redirect-in-host-authorization-middleware/78722",
            "https://github.com/advisories/GHSA-2rqw-v265-jf8c",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/actionpack/CVE-2021-22942.yml",
            "https://groups.google.com/g/rubyonrails-security/c/wB5tRn7h36c",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22942",
            "https://rubygems.org/gems/actionpack",
            "https://weblog.rubyonrails.org/2021/8/19/Rails-6-0-4-1-and-6-1-4-1-have-been-released/"
          ],
          "PublishedDate": "2021-10-18T13:15:00Z",
          "LastModifiedDate": "2021-12-22T17:33:00Z"
        },
        {
          "VulnerabilityID": "CVE-2022-23633",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.6, \u003e= 5.2.6.2, ~\u003e 6.0.4, \u003e= 6.0.4.6, ~\u003e 6.1.4, \u003e= 6.1.4.6, \u003e= 7.0.2.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-23633",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: information leak between requests",
          "Description": "Action Pack is a framework for handling and responding to web requests. Under certain circumstances response bodies will not be closed. In the event a response is *not* notified of a 'close', 'ActionDispatch::Executor' will not know to reset thread local state for the next request. This can lead to data being leaked to subsequent requests.This has been fixed in Rails 7.0.2.1, 6.1.4.5, 6.0.4.5, and 5.2.6.1. Upgrading is highly recommended, but to work around this problem a middleware described in GHSA-wh98-p28r-vrc9 can be used.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 4.3,
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2022/02/11/5",
            "https://access.redhat.com/security/cve/CVE-2022-23633",
            "https://discuss.rubyonrails.org/t/cve-2022-23633-possible-exposure-of-information-vulnerability-in-action-pack/80016",
            "https://github.com/advisories/GHSA-wh98-p28r-vrc9",
            "https://github.com/rails/rails/blob/7-0-stable/actionpack/CHANGELOG.md#rails-7021-february-11-2022",
            "https://github.com/rails/rails/commit/10c64a472f2f19a5e485bdac7d5106a76aeb29a5",
            "https://github.com/rails/rails/commit/f9a2ad03943d5c2ba54e1d45f155442b519c75da",
            "https://github.com/rails/rails/security/advisories/GHSA-wh98-p28r-vrc9",
            "https://groups.google.com/g/ruby-security-ann/c/FkTM-_7zSNA/m/K2RiMJBlBAAJ",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-23633",
            "https://rubyonrails.org/2022/2/11/Rails-7-0-2-2-6-1-4-6-6-0-4-6-and-5-2-6-2-have-been-released"
          ],
          "PublishedDate": "2022-02-11T21:15:00Z",
          "LastModifiedDate": "2022-02-22T21:47:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-8166",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.3, \u003e= 6.0.3.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8166",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: ability to forge per-form CSRF tokens given a global CSRF token",
          "Description": "A CSRF forgery vulnerability exists in rails \u003c 5.2.5, rails \u003c 6.0.4 that makes it possible for an attacker to, given a global CSRF token such as the one present in the authenticity_token meta tag, forge a per-form CSRF token.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-352"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 4.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
              "V3Score": 3.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8166",
            "https://github.com/advisories/GHSA-jp5v-5gx4-jmj9",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/actionpack/CVE-2020-8166.yml",
            "https://groups.google.com/forum/#!topic/rubyonrails-security/NOjKiGeXUgw",
            "https://groups.google.com/g/rubyonrails-security/c/NOjKiGeXUgw",
            "https://hackerone.com/reports/732415",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8166",
            "https://www.debian.org/security/2020/dsa-4766"
          ],
          "PublishedDate": "2020-07-02T19:15:00Z",
          "LastModifiedDate": "2020-11-20T17:47:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-8185",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "\u003e= 6.0.3.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8185",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-rails: untrusted users able to run pending migrations in production",
          "Description": "A denial of service vulnerability exists in Rails \u003c6.0.3.2 that allowed an untrusted user to run any pending migrations on a Rails app running in production.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 4,
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:H/A:L",
              "V3Score": 7.1
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8185",
            "https://github.com/advisories/GHSA-c6qr-h5vq-59jc",
            "https://github.com/rails/rails/commit/2121b9d20b60ed503aa041ef7b926d331ed79fc2",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/actionpack/CVE-2020-8185.yml",
            "https://groups.google.com/g/rubyonrails-security/c/pAe9EV8gbM0",
            "https://hackerone.com/reports/899069",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XJ7NUWXAEVRQCROIIBV4C6WXO6IR3KSB/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8185",
            "https://weblog.rubyonrails.org/2020/6/17/Rails-6-0-3-2-has-been-released"
          ],
          "PublishedDate": "2020-07-02T19:15:00Z",
          "LastModifiedDate": "2021-10-21T14:36:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-8264",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "\u003e= 6.0.3.4",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8264",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: possible XSS vulnerability in Action Pack in development mode",
          "Description": "In actionpack gem \u003e= 6.0.0, a possible XSS vulnerability exists when an application is running in development mode allowing an attacker to send or embed (in another page) a specially crafted URL which can allow the attacker to execute JavaScript in the context of the local application. This vulnerability is in the Actionable Exceptions middleware.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
              "V3Score": 7.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8264",
            "https://github.com/advisories/GHSA-35mm-cc6r-8fjp",
            "https://groups.google.com/g/rubyonrails-security/c/yQzUVfv42jk",
            "https://groups.google.com/g/rubyonrails-security/c/yQzUVfv42jk/m/oJWw-xhNAQAJ",
            "https://hackerone.com/reports/904059",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8264"
          ],
          "PublishedDate": "2021-01-06T21:15:00Z",
          "LastModifiedDate": "2021-01-12T14:17:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-22881",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 6.0.3, \u003e= 6.0.3.5, \u003e= 6.1.2.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-22881",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: open redirect vulnerability may lead to confidentiality and integrity compromise",
          "Description": "The Host Authorization middleware in Action Pack before 6.1.2.1, 6.0.3.5 suffers from an open redirect vulnerability. Specially crafted 'Host' headers in combination with certain \"allowed host\" formats can cause the Host Authorization middleware in Action Pack to redirect users to a malicious website. Impacted applications will have allowed hosts with a leading dot. When an allowed host contains a leading dot, a specially crafted 'Host' header can be used to redirect to a malicious website.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-601"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 5.8,
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            }
          },
          "References": [
            "http://www.openwall.com/lists/oss-security/2021/05/05/2",
            "http://www.openwall.com/lists/oss-security/2021/08/20/1",
            "http://www.openwall.com/lists/oss-security/2021/12/14/5",
            "https://access.redhat.com/security/cve/CVE-2021-22881",
            "https://benjamin-bouchet.com/cve-2021-22881-faille-de-securite-dans-le-middleware-hostauthorization/",
            "https://discuss.rubyonrails.org/t/cve-2021-22881-possible-open-redirect-in-host-authorization-middleware/77130",
            "https://github.com/advisories/GHSA-8877-prq4-9xfw",
            "https://groups.google.com/g/rubyonrails-security/c/zN_3qA26l6E",
            "https://hackerone.com/reports/1047447",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XQ3NS4IBYE2I3MVMGAHFZBZBIZGHXHT3/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22881",
            "https://rubygems.org/gems/actionpack"
          ],
          "PublishedDate": "2021-02-11T18:15:00Z",
          "LastModifiedDate": "2022-01-04T16:38:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-44528",
          "PkgName": "actionpack",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 6.0.4, \u003e= 6.0.4.2, ~\u003e 6.1.4, \u003e= 6.1.4.2, \u003e= 7.0.0.rc2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-44528",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionpack: specially crafted \"X-Forwarded-Host\" headers may lead to open redirect",
          "Description": "A open redirect vulnerability exists in Action Pack \u003e= 6.0.0 that could allow an attacker to craft a \"X-Forwarded-Host\" headers in combination with certain \"allowed host\" formats can cause the Host Authorization middleware in Action Pack to redirect users to a malicious website.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-601"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 5.8,
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
              "V3Score": 5.4
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-44528",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44528",
            "https://github.com/advisories/GHSA-qphc-hf5q-v8fc",
            "https://github.com/rails/rails/blob/v6.1.4.2/actionpack/CHANGELOG.md#rails-6142-december-14-2021",
            "https://github.com/rails/rails/commit/0fccfb9a3097a9c4260c791f1a40b128517e7815",
            "https://github.com/rails/rails/commit/0fccfb9a3097a9c4260c791f1a40b128517e7815 (master)",
            "https://github.com/rails/rails/commit/aecba3c301b80e9d5a63c30ea1b287bceaf2c107",
            "https://github.com/rails/rails/commit/aecba3c301b80e9d5a63c30ea1b287bceaf2c107 (v6.1.4.2)",
            "https://github.com/rails/rails/commit/fd6a64fef1d0f7f40a8d4b046da882e83163299c (v6.0.4.2)",
            "https://groups.google.com/g/ruby-security-ann/c/vG9gz3nk1pM/m/7-NU4MNrDAAJ",
            "https://groups.google.com/g/ruby-security-ann/c/vG9gz3nk1pM/m/7-NU4MNrDAAJ?utm_medium=email\u0026utm_source=footer",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44528",
            "https://www.openwall.com/lists/oss-security/2021/12/14/5"
          ],
          "PublishedDate": "2022-01-10T14:10:00Z",
          "LastModifiedDate": "2022-01-14T15:09:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-15169",
          "PkgName": "actionview",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.4, \u003e= 6.0.3.3",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-15169",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-activeview: Cross-site scripting in translation helpers",
          "Description": "In Action View before versions 5.2.4.4 and 6.0.3.3 there is a potential Cross-Site Scripting (XSS) vulnerability in Action View's translation helpers. Views that allow the user to control the default (not found) value of the 't' and 'translate' helpers could be susceptible to XSS attacks. When an HTML-unsafe string is passed as the default for a missing translation key named html or ending in _html, the default string is incorrectly marked as HTML-safe and not escaped. This is patched in versions 6.0.3.3 and 5.2.4.4. A workaround without upgrading is proposed in the source advisory.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 4.3,
              "V3Score": 6.1
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 6.1
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-15169",
            "https://github.com/advisories/GHSA-cfjv-5498-mph5",
            "https://github.com/rails/rails/commit/e663f084460ea56c55c3dc76f78c7caeddeeb02e",
            "https://github.com/rails/rails/security/advisories/GHSA-cfjv-5498-mph5",
            "https://groups.google.com/g/rubyonrails-security/c/b-C9kSGXYrc",
            "https://lists.debian.org/debian-lts-announce/2020/10/msg00015.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XJ7NUWXAEVRQCROIIBV4C6WXO6IR3KSB/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15169",
            "https://weblog.rubyonrails.org/2020/9/10/Rails-5-2-4-4-and-6-0-3-3-have-been-released",
            "https://www.debian.org/security/2020/dsa-4766"
          ],
          "PublishedDate": "2020-09-11T16:15:00Z",
          "LastModifiedDate": "2020-12-08T18:58:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-5267",
          "PkgName": "actionview",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.2, \u003e= 6.0.2.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-5267",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionview: views that use the 'j' or 'escape_javascript' methods are susceptible to XSS attacks",
          "Description": "In ActionView before versions 6.0.2.2 and 5.2.4.2, there is a possible XSS vulnerability in ActionView's JavaScript literal escape helpers. Views that use the 'j' or 'escape_javascript' methods may be susceptible to XSS attacks. The issue is fixed in versions 6.0.2.2 and 5.2.4.2.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79",
            "CWE-80"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:S/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 3.5,
              "V3Score": 4.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N",
              "V3Score": 4.8
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00019.html",
            "http://www.openwall.com/lists/oss-security/2020/03/19/1",
            "https://access.redhat.com/security/cve/CVE-2020-5267",
            "https://github.com/advisories/GHSA-65cv-r6x7-79hv",
            "https://github.com/rails/rails/commit/033a738817abd6e446e1b320cb7d1a5c15224e9a",
            "https://github.com/rails/rails/security/advisories/GHSA-65cv-r6x7-79hv",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/actionview/CVE-2020-5267.yml",
            "https://groups.google.com/forum/#!topic/rubyonrails-security/55reWMM_Pg8",
            "https://lists.debian.org/debian-lts-announce/2020/03/msg00022.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XJ7NUWXAEVRQCROIIBV4C6WXO6IR3KSB/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-5267",
            "https://www.openwall.com/lists/oss-security/2020/03/19/1"
          ],
          "PublishedDate": "2020-03-19T18:15:00Z",
          "LastModifiedDate": "2020-10-05T02:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-8167",
          "PkgName": "actionview",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.3, \u003e= 6.0.3.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8167",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-actionview: CSRF vulnerability in rails-ujs",
          "Description": "A CSRF vulnerability exists in rails \u003c= 6.0.3 rails-ujs module that could allow attackers to send CSRF tokens to wrong domains.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-352"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
              "V2Score": 4.3,
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8167",
            "https://github.com/advisories/GHSA-xq5j-gw7f-jgj8",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/actionview/CVE-2020-8167.yml",
            "https://groups.google.com/forum/#!topic/rubyonrails-security/x9DixQDG9a0",
            "https://groups.google.com/g/rubyonrails-security/c/x9DixQDG9a0",
            "https://hackerone.com/reports/189878",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8167",
            "https://www.debian.org/security/2020/dsa-4766"
          ],
          "PublishedDate": "2020-06-19T18:15:00Z",
          "LastModifiedDate": "2021-10-21T14:35:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-22880",
          "PkgName": "activerecord",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.5, ~\u003e 6.0.3, \u003e= 6.0.3.5, \u003e= 6.1.2.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-22880",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-activerecord: crafted input may cause a regular expression DoS",
          "Description": "The PostgreSQL adapter in Active Record before 6.1.2.1, 6.0.3.5, 5.2.4.5 suffers from a regular expression denial of service (REDoS) vulnerability. Carefully crafted input can cause the input validation in the 'money' type of the PostgreSQL adapter in Active Record to spend too much time in a regular expression, resulting in the potential for a DoS attack. This only impacts Rails applications that are using PostgreSQL along with money type columns that take user input.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-22880",
            "https://discuss.rubyonrails.org/t/cve-2021-22880-possible-dos-vulnerability-in-active-record-postgresql-adapter/77129",
            "https://github.com/advisories/GHSA-8hc4-xxm3-5ppp",
            "https://groups.google.com/g/rubyonrails-security/c/ZzUqCh9vyhI",
            "https://hackerone.com/reports/1023899",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MO5OJ3F4ZL3UXVLJO6ECANRVZBNRS2IH/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XQ3NS4IBYE2I3MVMGAHFZBZBIZGHXHT3/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-22880",
            "https://rubygems.org/gems/activerecord",
            "https://security.netapp.com/advisory/ntap-20210805-0009/",
            "https://www.debian.org/security/2021/dsa-4929"
          ],
          "PublishedDate": "2021-02-11T18:15:00Z",
          "LastModifiedDate": "2022-01-04T16:38:00Z"
        },
        {
          "VulnerabilityID": "CVE-2022-21831",
          "PkgName": "activestorage",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.6, \u003e= 5.2.6.3, ~\u003e 6.0.4, \u003e= 6.0.4.7, ~\u003e 6.1.4, \u003e= 6.1.4.7, \u003e= 7.0.2.3",
          "Layer": {},
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-21831",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-activestorage: Code injection vulnerability in ActiveStorage",
          "Description": "No description is available for this CVE.",
          "Severity": "CRITICAL",
          "CVSS": {
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-21831",
            "https://github.com/advisories/GHSA-w749-p3v6-hccq",
            "https://github.com/rails/rails/commit/0a72f7d670e9aa77a0bb8584cb1411ddabb7546e",
            "https://groups.google.com/g/rubyonrails-security/c/n-p-W1yxatI",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-21831",
            "https://rubysec.com/advisories/CVE-2022-21831/"
          ]
        },
        {
          "VulnerabilityID": "CVE-2020-8162",
          "PkgName": "activestorage",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.3, \u003e= 6.0.3.1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8162",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-activestorage: circumvention of file size limits in ActiveStorage",
          "Description": "A client side enforcement of server side security vulnerability exists in rails \u003c 5.2.4.2 and rails \u003c 6.0.3.1 ActiveStorage's S3 adapter that allows the Content-Length of a direct file upload to be modified by an end user bypassing upload limits.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-434"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8162",
            "https://github.com/advisories/GHSA-m42x-37p3-fv5w",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/activestorage/CVE-2020-8162.yml",
            "https://groups.google.com/forum/#!msg/rubyonrails-security/PjU3946mreQ/Dn-6uLbAAQAJ",
            "https://groups.google.com/forum/#!topic/rubyonrails-security/PjU3946mreQ",
            "https://groups.google.com/g/rubyonrails-security/c/PjU3946mreQ",
            "https://hackerone.com/reports/789579",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8162",
            "https://www.debian.org/security/2020/dsa-4766"
          ],
          "PublishedDate": "2020-06-19T17:15:00Z",
          "LastModifiedDate": "2020-09-25T12:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-8165",
          "PkgName": "activesupport",
          "InstalledVersion": "6.0.0",
          "FixedVersion": "~\u003e 5.2.4, \u003e= 5.2.4.3, \u003e= 6.0.3.1",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8165",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-activesupport: potentially unintended unmarshalling of user-provided objects in MemCacheStore and RedisCacheStore",
          "Description": "A deserialization of untrusted data vulnernerability exists in rails \u003c 5.2.4.3, rails \u003c 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE.",
          "Severity": "CRITICAL",
          "CweIDs": [
            "CWE-502"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V2Score": 7.5,
              "V3Score": 9.8
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "V3Score": 9.8
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00031.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00034.html",
            "https://access.redhat.com/security/cve/CVE-2020-8165",
            "https://github.com/advisories/GHSA-2p68-f74v-9wc6",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/activesupport/CVE-2020-8165.yml",
            "https://groups.google.com/forum/#!msg/rubyonrails-security/bv6fW4S0Y1c/KnkEqM7AAQAJ",
            "https://groups.google.com/forum/#!topic/rubyonrails-security/bv6fW4S0Y1c",
            "https://groups.google.com/g/rubyonrails-security/c/bv6fW4S0Y1c",
            "https://hackerone.com/reports/413388",
            "https://lists.debian.org/debian-lts-announce/2020/06/msg00022.html",
            "https://lists.debian.org/debian-lts-announce/2020/07/msg00013.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8165",
            "https://weblog.rubyonrails.org/2020/5/18/Rails-5-2-4-3-and-6-0-3-1-have-been-released/",
            "https://www.debian.org/security/2020/dsa-4766"
          ],
          "PublishedDate": "2020-06-19T18:15:00Z",
          "LastModifiedDate": "2020-10-17T12:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-32740",
          "PkgName": "addressable",
          "InstalledVersion": "2.6.0",
          "FixedVersion": "\u003e= 2.8.0",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-32740",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-addressable: ReDoS in templates",
          "Description": "Addressable is an alternative implementation to the URI implementation that is part of Ruby's standard library. An uncontrolled resource consumption vulnerability exists after version 2.3.0 through version 2.7.0. Within the URI template implementation in Addressable, a maliciously crafted template may result in uncontrolled resource consumption, leading to denial of service when matched against a URI. In typical usage, templates would not normally be read from untrusted user input, but nonetheless, no previous security advisory for Addressable has cautioned against doing this. Users of the parsing capabilities in Addressable but not the URI template capabilities are unaffected. The vulnerability is patched in version 2.8.0. As a workaround, only create Template objects from trusted sources that have been validated not to produce catastrophic backtracking.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-32740",
            "https://github.com/advisories/GHSA-jxhc-q857-3j6g",
            "https://github.com/sporkmonger/addressable/commit/0d8a3127e35886ce9284810a7f2438bff6b43cbc",
            "https://github.com/sporkmonger/addressable/commit/89c76130ce255c601f642a018cb5fb5a80e679a7",
            "https://github.com/sporkmonger/addressable/security/advisories/GHSA-jxhc-q857-3j6g",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SDFQM2NHNAZ3NNUQZEJTYECYZYXV4UDS/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/WYPVOOQU7UB277UUERJMCNQLRCXRCIQ5/",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-32740"
          ],
          "PublishedDate": "2021-07-06T15:15:00Z",
          "LastModifiedDate": "2021-09-21T18:18:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-15587",
          "PkgName": "loofah",
          "InstalledVersion": "2.2.3",
          "FixedVersion": "\u003e= 2.3.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-15587",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-loofah: XXS when a crafted SVG element is republished",
          "Description": "In the Loofah gem for Ruby through v2.3.0 unsanitized JavaScript may occur in sanitized output when a crafted SVG element is republished.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-79"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:S/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
              "V2Score": 3.5,
              "V3Score": 5.4
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
              "V3Score": 4.6
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-15587",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-15587",
            "https://github.com/advisories/GHSA-c3gv-9cxf-6f57",
            "https://github.com/flavorjones/loofah/issues/171",
            "https://hackerone.com/reports/709009",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4WK2UG7ORKRQOJ6E4XJ2NVIHYJES6BYZ/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/XMCWPLYPNIWYAY443IZZJ4IHBBLIHBP5/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-15587",
            "https://security.netapp.com/advisory/ntap-20191122-0003/",
            "https://ubuntu.com/security/notices/USN-4498-1",
            "https://usn.ubuntu.com/4498-1/",
            "https://www.debian.org/security/2019/dsa-4554"
          ],
          "PublishedDate": "2019-10-22T21:15:00Z",
          "LastModifiedDate": "2020-09-17T03:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-13117",
          "PkgName": "nokogiri",
          "InstalledVersion": "1.10.4",
          "FixedVersion": "\u003e= 1.10.5",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-13117",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "libxslt: an xsl number with certain format strings could lead to a uninitialized read in xsltNumberFormatInsertNumbers",
          "Description": "In numbers.c in libxslt 1.1.33, an xsl:number with certain format strings could lead to a uninitialized read in xsltNumberFormatInsertNumbers. This could allow an attacker to discern whether a byte on the stack contains the characters A, a, I, i, or 0, or any other character.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-908"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 3.3
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00062.html",
            "http://www.openwall.com/lists/oss-security/2019/11/17/2",
            "https://access.redhat.com/security/cve/CVE-2019-13117",
            "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=14471",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13117",
            "https://github.com/sparklemotion/nokogiri/issues/1943",
            "https://gitlab.gnome.org/GNOME/libxslt/commit/2232473733b7313d67de8836ea3b29eec6e8e285",
            "https://gitlab.gnome.org/GNOME/libxslt/commit/6ce8de69330783977dd14f6569419489875fb71b",
            "https://gitlab.gnome.org/GNOME/libxslt/commit/c5eb6cf3aba0af048596106ed839b4ae17ecbcb1",
            "https://groups.google.com/d/msg/ruby-security-ann/-Wq4aouIA3Q/yc76ZHemBgAJ",
            "https://lists.apache.org/thread.html/r58af02e294bd07f487e2c64ffc0a29b837db5600e33b6e698b9d696b@%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.apache.org/thread.html/rf4c02775860db415b4955778a131c2795223f61cb8c6a450893651e4@%3Cissues.bookkeeper.apache.org%3E",
            "https://lists.debian.org/debian-lts-announce/2019/07/msg00020.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IOYJKXPQCUNBMMQJWYXOR6QRUJZHEDRZ/",
            "https://oss-fuzz.com/testcase-detail/5631739747106816",
            "https://security.netapp.com/advisory/ntap-20190806-0004/",
            "https://security.netapp.com/advisory/ntap-20200122-0003/",
            "https://ubuntu.com/security/notices/USN-4164-1",
            "https://usn.ubuntu.com/4164-1/",
            "https://www.oracle.com/security-alerts/cpujan2020.html"
          ],
          "PublishedDate": "2019-07-01T02:15:00Z",
          "LastModifiedDate": "2021-06-29T15:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-7595",
          "PkgName": "nokogiri",
          "InstalledVersion": "1.10.4",
          "FixedVersion": "\u003e= 1.10.8",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-7595",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "libxml2: infinite loop in xmlStringLenDecodeEntities in some end-of-file situations",
          "Description": "xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file situation.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-835"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00047.html",
            "https://access.redhat.com/security/cve/CVE-2020-7595",
            "https://cert-portal.siemens.com/productcert/pdf/ssa-292794.pdf",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7595",
            "https://github.com/advisories/GHSA-7553-jr98-vx47",
            "https://github.com/sparklemotion/nokogiri/issues/1992",
            "https://gitlab.gnome.org/GNOME/libxml2/commit/0e1a49c89076",
            "https://linux.oracle.com/cve/CVE-2020-7595.html",
            "https://linux.oracle.com/errata/ELSA-2020-4479.html",
            "https://lists.debian.org/debian-lts-announce/2020/09/msg00009.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/545SPOI3ZPPNPX4TFRIVE4JVRTJRKULL/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5R55ZR52RMBX24TQTWHCIWKJVRV6YAWI/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JDPF3AAVKUAKDYFMFKSIQSVVS3EEFPQH/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7595",
            "https://security.gentoo.org/glsa/202010-04",
            "https://security.netapp.com/advisory/ntap-20200702-0005/",
            "https://ubuntu.com/security/notices/USN-4274-1",
            "https://us-cert.cisa.gov/ics/advisories/icsa-21-103-08",
            "https://usn.ubuntu.com/4274-1/",
            "https://www.oracle.com/security-alerts/cpujul2020.html",
            "https://www.oracle.com/security-alerts/cpuoct2021.html"
          ],
          "PublishedDate": "2020-01-21T23:15:00Z",
          "LastModifiedDate": "2021-12-08T19:51:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-30560",
          "PkgName": "nokogiri",
          "InstalledVersion": "1.10.4",
          "FixedVersion": "\u003e= 1.13.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-30560",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "Use after free in Blink XSLT in Google Chrome prior to 91.0.4472.164 a ...",
          "Description": "Use after free in Blink XSLT in Google Chrome prior to 91.0.4472.164 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-416"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
              "V2Score": 6.8,
              "V3Score": 8.8
            }
          },
          "References": [
            "https://chromereleases.googleblog.com/2021/07/stable-channel-update-for-desktop.html",
            "https://crbug.com/1219209",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30560",
            "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-fq42-c5rg-92c2"
          ],
          "PublishedDate": "2021-08-03T19:15:00Z",
          "LastModifiedDate": "2021-08-09T16:42:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-41098",
          "PkgName": "nokogiri",
          "InstalledVersion": "1.10.4",
          "FixedVersion": "\u003e= 1.12.5",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-41098",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-nokogiri: XEE on JRuby",
          "Description": "Nokogiri is a Rubygem providing HTML, XML, SAX, and Reader parsers with XPath and CSS selector support. In Nokogiri v1.12.4 and earlier, on JRuby only, the SAX parser resolves external entities by default. Users of Nokogiri on JRuby who parse untrusted documents using any of these classes are affected: Nokogiri::XML::SAX::Parse, Nokogiri::HTML4::SAX::Parser or its alias Nokogiri::HTML::SAX::Parser, Nokogiri::XML::SAX::PushParser, and Nokogiri::HTML4::SAX::PushParser or its alias Nokogiri::HTML::SAX::PushParser. JRuby users should upgrade to Nokogiri v1.12.5 or later to receive a patch for this issue. There are no workarounds available for v1.12.4 or earlier. CRuby users are not affected.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-611"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-41098",
            "https://github.com/advisories/GHSA-2rr5-8q37-2w7h",
            "https://github.com/sparklemotion/nokogiri/commit/5bf729ff3cc84709ee3c3248c981584088bf9f6d",
            "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-2rr5-8q37-2w7h",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41098"
          ],
          "PublishedDate": "2021-09-27T20:15:00Z",
          "LastModifiedDate": "2021-10-06T20:17:00Z"
        },
        {
          "VulnerabilityID": "GHSA-7rrm-v45f-jp64",
          "PkgName": "nokogiri",
          "InstalledVersion": "1.10.4",
          "FixedVersion": "\u003e= 1.11.4",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://github.com/advisories/GHSA-7rrm-v45f-jp64",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "Update packaged dependency libxml2 from 2.9.10 to 2.9.12",
          "Description": "### Summary\n\nNokogiri v1.11.4 updates the vendored libxml2 from v2.9.10 to v2.9.12 which addresses:\n\n- [CVE-2019-20388](https://security.archlinux.org/CVE-2019-20388) (Medium severity)\n- [CVE-2020-24977](https://security.archlinux.org/CVE-2020-24977) (Medium severity)\n- [CVE-2021-3517](https://security.archlinux.org/CVE-2021-3517) (Medium severity)\n- [CVE-2021-3518](https://security.archlinux.org/CVE-2021-3518) (Medium severity)\n- [CVE-2021-3537](https://security.archlinux.org/CVE-2021-3537) (Low severity)\n- [CVE-2021-3541](https://security.archlinux.org/CVE-2021-3541) (Low severity)\n\nNote that two additional CVEs were addressed upstream but are not relevant to this release. [CVE-2021-3516](https://security.archlinux.org/CVE-2021-3516) via 'xmllint' is not present in Nokogiri, and [CVE-2020-7595](https://security.archlinux.org/CVE-2020-7595) has been patched in Nokogiri since v1.10.8 (see #1992).\n\nPlease note that this advisory only applies to the CRuby implementation of Nokogiri '\u003c 1.11.4', and only if the packaged version of libxml2 is being used. If you've overridden defaults at installation time to use system libraries instead of packaged libraries, you should instead pay attention to your distro's 'libxml2' release announcements.\n\n\n### Mitigation\n\nUpgrade to Nokogiri '\u003e= 1.11.4'.\n\n\n### Impact\n\nI've done a brief analysis of the published CVEs that are addressed in this upstream release. The libxml2 maintainers have not released a canonical set of CVEs, and so this list is pieced together from secondary sources and may be incomplete.\n\nAll information below is sourced from [security.archlinux.org](https://security.archlinux.org), which appears to have the most up-to-date information as of this analysis.\n\n#### [CVE-2019-20388](https://security.archlinux.org/CVE-2019-20388)\n\n- **Severity**: Medium\n- **Type**: Denial of service\n- **Description**: A memory leak was found in the xmlSchemaValidateStream function of libxml2. Applications that use this library may be vulnerable to memory not being freed leading to a denial of service.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/commit/7ffcd44d7e6c46704f8af0321d9314cd26e0e18a\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri \u003c v1.11.4.\n\n\n#### [CVE-2020-7595](https://security.archlinux.org/CVE-2020-7595)\n\n- **Severity**: Medium\n- **Type**: Denial of service\n- **Description**: xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file situation.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/commit/0e1a49c8907645d2e155f0d89d4d9895ac5112b5\n\nThis has been patched in Nokogiri since v1.10.8 (see #1992).\n\n\n#### [CVE-2020-24977](https://security.archlinux.org/CVE-2020-24977)\n\n- **Severity**: Medium\n- **Type**: Information disclosure\n- **Description**: GNOME project libxml2 \u003c= 2.9.10 has a global buffer over-read vulnerability in xmlEncodeEntitiesInternal at libxml2/entities.c.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/commit/50f06b3efb638efb0abd95dc62dca05ae67882c2\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri \u003c v1.11.4.\n\n\n#### [CVE-2021-3516](https://security.archlinux.org/CVE-2021-3516)\n\n- **Severity**: Medium\n- **Type**: Arbitrary code execution (no remote vector)\n- **Description**: A use-after-free security issue was found libxml2 before version 2.9.11 when \"xmllint --html --push\" is used to process crafted files.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/230\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/1358d157d0bd83be1dfe356a69213df9fac0b539\n\nVerified that the fix commit first appears in v2.9.11. This vector does not exist within Nokogiri, which does not ship 'xmllint'.\n\n\n#### [CVE-2021-3517](https://security.archlinux.org/CVE-2021-3517)\n\n- **Severity**: Medium\n- **Type**: Arbitrary code execution\n- **Description**: A heap-based buffer overflow was found in libxml2 before version 2.9.11 when processing truncated UTF-8 input.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/235\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri \u003c v1.11.4.\n\n\n#### [CVE-2021-3518](https://security.archlinux.org/CVE-2021-3518)\n\n- **Severity**: Medium\n- **Type**: Arbitrary code execution\n- **Description**: A use-after-free security issue was found in libxml2 before version 2.9.11 in xmlXIncludeDoProcess() in xinclude.c when processing crafted files.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/237\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/1098c30a040e72a4654968547f415be4e4c40fe7\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri \u003c v1.11.4.\n\n\n#### [CVE-2021-3537](https://security.archlinux.org/CVE-2021-3537)\n\n- **Severity**: Low\n- **Type**: Denial of service\n- **Description**: It was found that libxml2 before version 2.9.11 did not propagate errors while parsing XML mixed content, causing a NULL dereference. If an untrusted XML document was parsed in recovery mode and post-validated, the flaw could be used to crash the application.\n- **Issue**: https://gitlab.gnome.org/GNOME/libxml2/-/issues/243\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/babe75030c7f64a37826bb3342317134568bef61\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri \u003c v1.11.4.\n\n\n#### [CVE-2021-3541](https://security.archlinux.org/CVE-2021-3541)\n\n- **Severity**: Low\n- **Type**: Denial of service\n- **Description**: A security issue was found in libxml2 before version 2.9.11. Exponential entity expansion attack its possible bypassing all existing protection mechanisms and leading to denial of service.\n- **Fixed**: https://gitlab.gnome.org/GNOME/libxml2/-/commit/8598060bacada41a0eb09d95c97744ff4e428f8e\n\nVerified that the fix commit first appears in v2.9.11. It seems possible that this issue would be present in programs using Nokogiri \u003c v1.11.4, however Nokogiri's default parse options prevent the attack from succeeding (it is necessary to opt into 'DTDLOAD' which is off by default).\n\nFor more details supporting this analysis of this CVE, please visit #2233.\n",
          "Severity": "HIGH",
          "References": [
            "https://github.com/advisories/GHSA-7rrm-v45f-jp64",
            "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-7rrm-v45f-jp64"
          ]
        },
        {
          "VulnerabilityID": "GHSA-fq42-c5rg-92c2",
          "PkgName": "nokogiri",
          "InstalledVersion": "1.10.4",
          "FixedVersion": "1.13.2",
          "Layer": {},
          "SeveritySource": "ghsa",
          "PrimaryURL": "https://github.com/advisories/GHSA-fq42-c5rg-92c2",
          "DataSource": {
            "ID": "ghsa",
            "Name": "GitHub Security Advisory Rubygems",
            "URL": "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arubygems"
          },
          "Title": "Vulnerable dependencies in Nokogiri",
          "Description": "### Summary\n\nNokogiri [v1.13.2](https://github.com/sparklemotion/nokogiri/releases/tag/v1.13.2) upgrades two of its packaged dependencies:\n\n- vendored libxml2 from v2.9.12 to [v2.9.13](https://download.gnome.org/sources/libxml2/2.9/libxml2-2.9.13.news)\n- vendored libxslt from v1.1.34 to [v1.1.35](https://download.gnome.org/sources/libxslt/1.1/libxslt-1.1.35.news)\n\nThose library versions address the following upstream CVEs:\n\n- libxslt: [CVE-2021-30560](https://nvd.nist.gov/vuln/detail/CVE-2021-30560) (CVSS 8.8, High severity)\n- libxml2: [CVE-2022-23308](https://nvd.nist.gov/vuln/detail/CVE-2022-23308) (Unspecified severity, see more information below)\n\nThose library versions also address numerous other issues including performance improvements, regression fixes, and bug fixes, as well as memory leaks and other use-after-free issues that were not assigned CVEs.\n\nPlease note that this advisory only applies to the CRuby implementation of Nokogiri '\u003c 1.13.2', and only if the _packaged_ libraries are being used. If you've overridden defaults at installation time to use _system_ libraries instead of packaged libraries, you should instead pay attention to your distro's 'libxml2' and 'libxslt' release announcements.\n\n\n### Mitigation\n\nUpgrade to Nokogiri '\u003e= 1.13.2'.\n\nUsers who are unable to upgrade Nokogiri may also choose a more complicated mitigation: compile and link an older version Nokogiri against external libraries libxml2 '\u003e= 2.9.13' and libxslt '\u003e= 1.1.35', which will also address these same CVEs.\n\n\n### Impact\n\n#### libxslt [CVE-2021-30560](https://nvd.nist.gov/vuln/detail/CVE-2021-30560)\n\n- CVSS3 score: 8.8 (High)\n- Fixed by https://gitlab.gnome.org/GNOME/libxslt/-/commit/50f9c9c\n\nAll versions of libxslt prior to v1.1.35 are affected.\n\nApplications using **untrusted** XSL stylesheets to transform XML are vulnerable to a denial-of-service attack and should be upgraded immediately.\n\n\n#### libxml2 [CVE-2022-23308](https://nvd.nist.gov/vuln/detail/CVE-2022-23308)\n\n- As of the time this security advisory was published, there is no officially published information available about this CVE's severity. The above NIST link does not yet have a published record, and the libxml2 maintainer has declined to provide a severity score.\n- Fixed by https://gitlab.gnome.org/GNOME/libxml2/-/commit/652dd12\n- Further explanation is at https://mail.gnome.org/archives/xml/2022-February/msg00015.html\n\nThe upstream commit and the explanation linked above indicate that an application may be vulnerable to a denial of service, memory disclosure, or code execution if it parses an **untrusted** document with parse options 'DTDVALID' set to true, and 'NOENT' set to false.\n\nAn analysis of these parse options:\n\n- While 'NOENT' is off by default for Document, DocumentFragment, Reader, and Schema parsing, it is on by default for XSLT (stylesheet) parsing in Nokogiri v1.12.0 and later.\n- 'DTDVALID' is an option that Nokogiri does not set for any operations, and so this CVE applies only to applications setting this option explicitly.\n\nIt seems reasonable to assume that any application explicitly setting the parse option 'DTDVALID' when parsing **untrusted** documents is vulnerable and should be upgraded immediately.\n",
          "Severity": "HIGH",
          "References": [
            "https://github.com/advisories/GHSA-fq42-c5rg-92c2",
            "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-fq42-c5rg-92c2"
          ]
        },
        {
          "VulnerabilityID": "CVE-2020-26247",
          "PkgName": "nokogiri",
          "InstalledVersion": "1.10.4",
          "FixedVersion": "\u003e= 1.11.0.rc4",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-26247",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-nokogiri: XML external entity injection via Nokogiri::XML::Schema",
          "Description": "Nokogiri is a Rubygem providing HTML, XML, SAX, and Reader parsers with XPath and CSS selector support. In Nokogiri before version 1.11.0.rc4 there is an XXE vulnerability. XML Schemas parsed by Nokogiri::XML::Schema are trusted by default, allowing external resources to be accessed over the network, potentially enabling XXE or SSRF attacks. This behavior is counter to the security policy followed by Nokogiri maintainers, which is to treat all input as untrusted by default whenever possible. This is fixed in Nokogiri version 1.11.0.rc4.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-611"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V2Score": 4,
              "V3Score": 4.3
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
              "V3Score": 4.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-26247",
            "https://github.com/advisories/GHSA-vr8q-g5c7-m54m",
            "https://github.com/sparklemotion/nokogiri/blob/main/CHANGELOG.md#v1110--2021-01-03",
            "https://github.com/sparklemotion/nokogiri/commit/9c87439d9afa14a365ff13e73adc809cb2c3d97b",
            "https://github.com/sparklemotion/nokogiri/releases/tag/v1.11.0.rc4",
            "https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-vr8q-g5c7-m54m",
            "https://hackerone.com/reports/747489",
            "https://lists.debian.org/debian-lts-announce/2021/06/msg00007.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-26247",
            "https://rubygems.org/gems/nokogiri"
          ],
          "PublishedDate": "2020-12-30T19:15:00Z",
          "LastModifiedDate": "2021-06-06T21:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-16770",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 3.12.2, \u003e= 4.3.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-16770",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: keepalive requests from poorly-behaved client leads to denial of service",
          "Description": "In Puma before versions 3.12.2 and 4.3.1, a poorly-behaved client could use keepalive requests to monopolize Puma's reactor and create a denial of service attack. If more keepalive connections to Puma are opened than there are threads available, additional connections will wait permanently if the attacker sends requests frequently enough. This vulnerability is patched in Puma 4.3.1 and 3.12.2.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-770"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2019-16770",
            "https://github.com/advisories/GHSA-7xx3-m584-x994",
            "https://github.com/puma/puma/security/advisories/GHSA-7xx3-m584-x994",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-16770"
          ],
          "PublishedDate": "2019-12-05T20:15:00Z",
          "LastModifiedDate": "2020-05-06T15:07:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-11076",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 3.12.5, \u003e= 4.3.4",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-11076",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: HTTP Smuggling via an invalid Transfer-Encoding Header",
          "Description": "In Puma (RubyGem) before 4.3.4 and 3.12.5, an attacker could smuggle an HTTP response, by using an invalid transfer-encoding header. The problem has been fixed in Puma 3.12.5 and Puma 4.3.4.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-444",
            "CWE-444"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00034.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00038.html",
            "https://access.redhat.com/security/cve/CVE-2020-11076",
            "https://github.com/advisories/GHSA-x7jg-6pwg-fx5h",
            "https://github.com/puma/puma/blob/master/History.md#434435-and-31253126--2020-05-22",
            "https://github.com/puma/puma/commit/f24d5521295a2152c286abb0a45a1e1e2bd275bd",
            "https://github.com/puma/puma/security/advisories/GHSA-x7jg-6pwg-fx5h",
            "https://lists.debian.org/debian-lts-announce/2020/10/msg00009.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SKIY5H67GJIGJL6SMFWFLUQQQR3EMVPR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-11076"
          ],
          "PublishedDate": "2020-05-22T15:15:00Z",
          "LastModifiedDate": "2020-10-07T13:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-29509",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 4.3.8, \u003e= 5.3.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-29509",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: incomplete fix for CVE-2019-16770 allows Denial of Service (DoS)",
          "Description": "Puma is a concurrent HTTP 1.1 server for Ruby/Rack applications. The fix for CVE-2019-16770 was incomplete. The original fix only protected existing connections that had already been accepted from having their requests starved by greedy persistent-connections saturating all threads in the same process. However, new connections may still be starved by greedy persistent-connections saturating all threads in all processes in the cluster. A 'puma' server which received more concurrent 'keep-alive' connections than the server had threads in its threadpool would service only a subset of connections, denying service to the unserved connections. This problem has been fixed in 'puma' 4.3.8 and 5.3.1. Setting 'queue_requests false' also fixes the issue. This is not advised when using 'puma' without a reverse proxy, such as 'nginx' or 'apache', because you will open yourself to slow client attacks (e.g. slowloris). The fix is very small and a git patch is available for those using unsupported versions of Puma.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-29509",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29509",
            "https://gist.github.com/nateberkopec/4b3ea5676c0d70cbb37c82d54be25837",
            "https://github.com/advisories/GHSA-q28m-8xjw-8vr5",
            "https://github.com/puma/puma/security/advisories/GHSA-q28m-8xjw-8vr5",
            "https://github.com/puma/puma/security/policy",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-29509",
            "https://rubygems.org/gems/puma"
          ],
          "PublishedDate": "2021-05-11T17:15:00Z",
          "LastModifiedDate": "2021-05-24T19:30:00Z"
        },
        {
          "VulnerabilityID": "CVE-2022-23634",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 4.3.11, \u003e= 5.6.2",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-23634",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: rubygem-rails: information leak between requests",
          "Description": "Puma is a Ruby/Rack web server built for parallelism. Prior to 'puma' version '5.6.2', 'puma' may not always call 'close' on the response body. Rails, prior to version '7.0.2.2', depended on the response body being closed in order for its 'CurrentAttributes' implementation to work correctly. The combination of these two behaviors (Puma not closing the body + Rails' Executor implementation) causes information leakage. This problem is fixed in Puma versions 5.6.2 and 4.3.11. This problem is fixed in Rails versions 7.02.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2. Upgrading to a patched Rails _or_ Puma version fixes the vulnerability.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 4.3,
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N",
              "V3Score": 8
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2022-23634",
            "https://github.com/advisories/GHSA-rmj8-8hhh-gv5h",
            "https://github.com/advisories/GHSA-wh98-p28r-vrc9",
            "https://github.com/puma/puma/commit/b70f451fe8abc0cff192c065d549778452e155bb",
            "https://github.com/puma/puma/security/advisories/GHSA-rmj8-8hhh-gv5h",
            "https://groups.google.com/g/ruby-security-ann/c/FkTM-_7zSNA/m/K2RiMJBlBAAJ?utm_medium=email\u0026utm_source=footer\u0026pli=1",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-23634"
          ],
          "PublishedDate": "2022-02-11T22:15:00Z",
          "LastModifiedDate": "2022-02-22T21:58:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-11077",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 3.12.6, \u003e= 4.3.5",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-11077",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: HTTP Smuggling through a proxy via Transfer-Encoding Header",
          "Description": "In Puma (RubyGem) before 4.3.5 and 3.12.6, a client could smuggle a request through a proxy, causing the proxy to send a response back to another unknown client. If the proxy uses persistent connections and the client adds another request in via HTTP pipelining, the proxy may mistake it as the first request's body. Puma, however, would see it as two requests, and when processing the second request, send back a response that the proxy does not expect. If the proxy has reused the persistent connection to Puma to send another request for a different client, the second response from the first client will be sent to the second client. This is a similar but different vulnerability from CVE-2020-11076. The problem has been fixed in Puma 3.12.6 and Puma 4.3.5.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-444",
            "CWE-444"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",
              "V3Score": 6.8
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00034.html",
            "http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00038.html",
            "https://access.redhat.com/security/cve/CVE-2020-11077",
            "https://github.com/advisories/GHSA-w64w-qqph-5gxm",
            "https://github.com/puma/puma/blob/master/History.md#434435-and-31253126--2020-05-22",
            "https://github.com/puma/puma/security/advisories/GHSA-w64w-qqph-5gxm",
            "https://lists.debian.org/debian-lts-announce/2020/10/msg00009.html",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SKIY5H67GJIGJL6SMFWFLUQQQR3EMVPR/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-11077"
          ],
          "PublishedDate": "2020-05-22T15:15:00Z",
          "LastModifiedDate": "2020-10-07T13:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-5247",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 3.12.4, \u003e= 4.3.3",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-5247",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: attacker is able to use newline characters to insert malicious content (HTTP Response Splitting), this could lead to XSS",
          "Description": "In Puma (RubyGem) before 4.3.2 and before 3.12.3, if an application using Puma allows untrusted input in a response header, an attacker can use newline characters (i.e. 'CR', 'LF' or'/r', '/n') to end the header and inject malicious content, such as additional headers or an entirely new response body. This vulnerability is known as HTTP Response Splitting. While not an attack in itself, response splitting is a vector for several other attacks, such as cross-site scripting (XSS). This is related to CVE-2019-16254, which fixed this vulnerability for the WEBrick Ruby web server. This has been fixed in versions 4.3.2 and 3.12.3 by checking all headers for line endings and rejecting headers with those characters.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-74"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-5247",
            "https://github.com/advisories/GHSA-84j7-475p-hp8v",
            "https://github.com/puma/puma/commit/c36491756f68a9d6a8b3a49e7e5eb07fe6f1332f",
            "https://github.com/puma/puma/security/advisories/GHSA-84j7-475p-hp8v",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BMJ3CGZ3DLBJ5WUUKMI5ZFXFJQMXJZIK/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DIHVO3CQMU7BZC7FCTSRJ33YDNS3GFPK/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NJ3LL5F5QADB6LM46GXZETREAKZMQNRD/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-5247",
            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
            "https://www.ruby-lang.org/en/news/2019/10/01/http-response-splitting-in-webrick-cve-2019-16254"
          ],
          "PublishedDate": "2020-02-28T17:15:00Z",
          "LastModifiedDate": "2020-04-09T17:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-5249",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 3.12.4, \u003e= 4.3.3",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-5249",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: attacker is able to use carriage return character to insert malicious content (HTTP Response Splitting), this could lead to XSS",
          "Description": "In Puma (RubyGem) before 4.3.3 and 3.12.4, if an application using Puma allows untrusted input in an early-hints header, an attacker can use a carriage return character to end the header and inject malicious content, such as additional headers or an entirely new response body. This vulnerability is known as HTTP Response Splitting. While not an attack in itself, response splitting is a vector for several other attacks, such as cross-site scripting (XSS). This is related to CVE-2020-5247, which fixed this vulnerability but only for regular responses. This has been fixed in 4.3.3 and 3.12.4.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-74"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:S/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 4,
              "V3Score": 6.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 5.3
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-5249",
            "https://github.com/advisories/GHSA-33vf-4xgg-9r58",
            "https://github.com/puma/puma/commit/c22712fc93284a45a93f9ad7023888f3a65524f3",
            "https://github.com/puma/puma/security/advisories/GHSA-33vf-4xgg-9r58",
            "https://github.com/puma/puma/security/advisories/GHSA-84j7-475p-hp8v",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/BMJ3CGZ3DLBJ5WUUKMI5ZFXFJQMXJZIK/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DIHVO3CQMU7BZC7FCTSRJ33YDNS3GFPK/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/NJ3LL5F5QADB6LM46GXZETREAKZMQNRD/",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-5249",
            "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"
          ],
          "PublishedDate": "2020-03-02T16:15:00Z",
          "LastModifiedDate": "2020-04-09T17:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2021-41136",
          "PkgName": "puma",
          "InstalledVersion": "3.12.1",
          "FixedVersion": "~\u003e 4.3.9, \u003e= 5.5.1",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-41136",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-puma: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') in puma",
          "Description": "Puma is a HTTP 1.1 server for Ruby/Rack applications. Prior to versions 5.5.1 and 4.3.9, using 'puma' with a proxy which forwards HTTP header values which contain the LF character could allow HTTP request smugggling. A client could smuggle a request through a proxy, causing the proxy to send a response back to another unknown client. The only proxy which has this behavior, as far as the Puma team is aware of, is Apache Traffic Server. If the proxy uses persistent connections and the client adds another request in via HTTP pipelining, the proxy may mistake it as the first request's body. Puma, however, would see it as two requests, and when processing the second request, send back a response that the proxy does not expect. If the proxy has reused the persistent connection to Puma to send another request for a different client, the second response from the first client will be sent to the second client. This vulnerability was patched in Puma 5.5.1 and 4.3.9. As a workaround, do not use Apache Traffic Server with 'puma'.",
          "Severity": "LOW",
          "CweIDs": [
            "CWE-444"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:H/Au:S/C:P/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
              "V2Score": 3.6,
              "V3Score": 3.7
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
              "V3Score": 3.7
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2021-41136",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41136",
            "https://github.com/advisories/GHSA-48w2-rm65-62xx",
            "https://github.com/puma/puma/commit/acdc3ae571dfae0e045cf09a295280127db65c7f",
            "https://github.com/puma/puma/releases/tag/v4.3.9",
            "https://github.com/puma/puma/releases/tag/v5.5.1",
            "https://github.com/puma/puma/security/advisories/GHSA-48w2-rm65-62xx",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41136"
          ],
          "PublishedDate": "2021-10-12T16:15:00Z",
          "LastModifiedDate": "2021-10-27T15:21:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-8161",
          "PkgName": "rack",
          "InstalledVersion": "2.0.7",
          "FixedVersion": "~\u003e 2.1.3, \u003e= 2.2.0",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8161",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-rack: directory traversal in Rack::Directory",
          "Description": "A directory traversal vulnerability exists in rack \u003c 2.2.0 that allows an attacker perform directory traversal vulnerability in the Rack::Directory app that is bundled with Rack which could result in information disclosure.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-22"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
              "V2Score": 5,
              "V3Score": 8.6
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8161",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8161",
            "https://github.com/advisories/GHSA-5f9h-9pjv-v6j7",
            "https://github.com/rack/rack/commit/dddb7ad18ed79ca6ab06ccc417a169fde451246e",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/rack/CVE-2020-8161.yml",
            "https://groups.google.com/forum/#!msg/rubyonrails-security/IOO1vNZTzPA/Ylzi1UYLAAAJ",
            "https://groups.google.com/forum/#!topic/ruby-security-ann/T4ZIsfRf2eA",
            "https://groups.google.com/g/rubyonrails-security/c/IOO1vNZTzPA",
            "https://hackerone.com/reports/434404",
            "https://lists.debian.org/debian-lts-announce/2020/07/msg00006.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8161",
            "https://ubuntu.com/security/notices/USN-4561-1",
            "https://ubuntu.com/security/notices/USN-4561-2",
            "https://usn.ubuntu.com/4561-1/"
          ],
          "PublishedDate": "2020-07-02T19:15:00Z",
          "LastModifiedDate": "2020-10-05T23:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-8184",
          "PkgName": "rack",
          "InstalledVersion": "2.0.7",
          "FixedVersion": "~\u003e 2.1.4, \u003e= 2.2.3",
          "Layer": {},
          "SeveritySource": "nvd",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8184",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-rack: percent-encoded cookies can be used to overwrite existing prefixed cookie names",
          "Description": "A reliance on cookies without validation/integrity check security vulnerability exists in rack \u003c 2.2.3, rack \u003c 2.1.4 that makes it is possible for an attacker to forge a secure or host-only cookie prefix.",
          "Severity": "HIGH",
          "CweIDs": [
            "CWE-20"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:P/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-8184",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-8184",
            "https://github.com/advisories/GHSA-j6w9-fv6q-3q52",
            "https://github.com/rack/rack/commit/1f5763de6a9fe515ff84992b343d63c88104654c",
            "https://github.com/rubysec/ruby-advisory-db/blob/master/gems/rack/CVE-2020-8184.yml",
            "https://groups.google.com/forum/#!msg/rubyonrails-security/OWtmozPH9Ak/4m00yHPCBAAJ",
            "https://groups.google.com/g/rubyonrails-security/c/OWtmozPH9Ak",
            "https://hackerone.com/reports/895727",
            "https://lists.debian.org/debian-lts-announce/2020/07/msg00006.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-8184",
            "https://ubuntu.com/security/notices/USN-4561-1",
            "https://ubuntu.com/security/notices/USN-4561-2",
            "https://usn.ubuntu.com/4561-1/"
          ],
          "PublishedDate": "2020-06-19T17:15:00Z",
          "LastModifiedDate": "2020-10-05T23:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-16782",
          "PkgName": "rack",
          "InstalledVersion": "2.0.7",
          "FixedVersion": "~\u003e 1.6.12, \u003e= 2.0.8",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-16782",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-rack: hijack sessions by using timing attacks targeting the session id",
          "Description": "There's a possible information leak / session hijack vulnerability in Rack (RubyGem rack). This vulnerability is patched in versions 1.6.12 and 2.0.8. Attackers may be able to find and hijack sessions by using timing attacks targeting the session id. Session ids are usually stored and indexed in a database that uses some kind of scheme for speeding up lookups of that session id. By carefully measuring the amount of time it takes to look up a session, an attacker may be able to find a valid session id and hijack the session. The session id itself may be generated randomly, but the way the session is indexed by the backing store does not use a secure comparison.",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-203"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:P/I:N/A:N",
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V2Score": 4.3,
              "V3Score": 5.9
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
              "V3Score": 5.9
            }
          },
          "References": [
            "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00016.html",
            "http://www.openwall.com/lists/oss-security/2019/12/18/2",
            "http://www.openwall.com/lists/oss-security/2019/12/18/3",
            "http://www.openwall.com/lists/oss-security/2019/12/19/3",
            "http://www.openwall.com/lists/oss-security/2020/04/08/1",
            "http://www.openwall.com/lists/oss-security/2020/04/09/2",
            "https://access.redhat.com/security/cve/CVE-2019-16782",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16782",
            "https://github.com/advisories/GHSA-hrqr-hxpp-chr3",
            "https://github.com/rack/rack/commit/7fecaee81f59926b6e1913511c90650e76673b38",
            "https://github.com/rack/rack/security/advisories/GHSA-hrqr-hxpp-chr3",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HZXMWILCICQLA2BYSP6I2CRMUG53YBLX/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-16782"
          ],
          "PublishedDate": "2019-12-18T20:15:00Z",
          "LastModifiedDate": "2021-11-02T18:04:00Z"
        },
        {
          "VulnerabilityID": "CVE-2019-16892",
          "PkgName": "rubyzip",
          "InstalledVersion": "1.2.3",
          "FixedVersion": "\u003e= 1.3.0",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-16892",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "cfme: rubygem-rubyzip denial of service via crafted ZIP file",
          "Description": "In Rubyzip before 1.3.0, a crafted ZIP file can bypass application checks on ZIP entry sizes because data about the uncompressed size can be spoofed. This allows attackers to cause a denial of service (disk consumption).",
          "Severity": "MEDIUM",
          "CweIDs": [
            "CWE-400"
          ],
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:M/Au:N/C:N/I:N/A:C",
              "V3Vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V2Score": 7.1,
              "V3Score": 5.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
              "V3Score": 5.5
            }
          },
          "References": [
            "https://access.redhat.com/errata/RHBA-2019:4047",
            "https://access.redhat.com/errata/RHSA-2019:4201",
            "https://access.redhat.com/security/cve/CVE-2019-16892",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16892",
            "https://github.com/advisories/GHSA-5m2v-hc64-56h6",
            "https://github.com/jdleesmiller/ruby-advisory-db/blob/master/gems/rubyzip/CVE-2019-16892.yml",
            "https://github.com/rubyzip/rubyzip/commit/4167f0ce67e42b082605bca75c7bdfd01eb23804",
            "https://github.com/rubyzip/rubyzip/commit/7849f7362ab0cd23d5730ef8b6f2c39252da2285",
            "https://github.com/rubyzip/rubyzip/commit/97cb6aefe6d12bd2429d7a2e119ccb26f259d71d",
            "https://github.com/rubyzip/rubyzip/pull/403",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/J45KSFPP6DFVWLC7Z73L7SX735CKZYO6/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/MWWPORMSBHZTMP4PGF4DQD22TTKBQMMC/",
            "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/X255K6ZBAQC462PQN2ND5HOTTQEJ2G2X/",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-16892"
          ],
          "PublishedDate": "2019-09-25T22:15:00Z",
          "LastModifiedDate": "2019-11-22T03:15:00Z"
        },
        {
          "VulnerabilityID": "CVE-2020-7663",
          "PkgName": "websocket-extensions",
          "InstalledVersion": "0.1.4",
          "FixedVersion": "\u003e= 0.1.5",
          "Layer": {},
          "SeveritySource": "ruby-advisory-db",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-7663",
          "DataSource": {
            "ID": "ruby-advisory-db",
            "Name": "Ruby Advisory Database",
            "URL": "https://github.com/rubysec/ruby-advisory-db"
          },
          "Title": "rubygem-websocket-extensions: ReDoS vulnerability in Sec-WebSocket-Extensions parser",
          "Description": "websocket-extensions ruby module prior to 0.1.5 allows Denial of Service (DoS) via Regex Backtracking. The extension parser may take quadratic time when parsing a header containing an unclosed string parameter value whose content is a repeating two-byte sequence of a backslash and some other character. This could be abused by an attacker to conduct Regex Denial Of Service (ReDoS) on a single-threaded server by providing a malicious payload with the Sec-WebSocket-Extensions header.",
          "Severity": "HIGH",
          "CVSS": {
            "nvd": {
              "V2Vector": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V2Score": 5,
              "V3Score": 7.5
            },
            "redhat": {
              "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "V3Score": 7.5
            }
          },
          "References": [
            "https://access.redhat.com/security/cve/CVE-2020-7663",
            "https://blog.jcoglan.com/2020/06/02/redos-vulnerability-in-websocket-extensions",
            "https://blog.jcoglan.com/2020/06/02/redos-vulnerability-in-websocket-extensions/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7663",
            "https://github.com/advisories/GHSA-g6wq-qcwm-j5g2",
            "https://github.com/faye/websocket-extensions-ruby/commit/aa156a439da681361ed6f53f1a8131892418838b",
            "https://github.com/faye/websocket-extensions-ruby/security/advisories/GHSA-g6wq-qcwm-j5g2",
            "https://lists.debian.org/debian-lts-announce/2020/08/msg00031.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-7663",
            "https://snyk.io/vuln/SNYK-RUBY-WEBSOCKETEXTENSIONS-570830",
            "https://ubuntu.com/security/notices/USN-4502-1",
            "https://usn.ubuntu.com/4502-1/"
          ],
          "PublishedDate": "2020-06-02T19:15:00Z",
          "LastModifiedDate": "2020-09-17T15:15:00Z"
        }
      ]
    }
  ]
}
`

const configOutput = `
{
  "SchemaVersion": 2,
  "ArtifactName": ".",
  "ArtifactType": "filesystem",
  "Metadata": {
    "ImageConfig": {
      "architecture": "",
      "created": "0001-01-01T00:00:00Z",
      "os": "",
      "rootfs": {
        "type": "",
        "diff_ids": null
      },
      "config": {}
    }
  },
  "Results": [
    {
      "Target": "../../../../../../../examples/hcl/example1/main.tf",
      "Class": "config",
      "Type": "terraform",
      "MisconfSummary": {
        "Successes": 1,
        "Failures": 5,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Terraform Security Check",
          "ID": "AVD-AWS-0054",
          "Title": "Use of plain HTTP.",
          "Description": "Your traffic is not protected",
          "Message": "Listener for application load balancer does not use HTTPS.",
          "Resolution": "Switch to HTTPS to benefit from TLS security features",
          "Severity": "CRITICAL",
          "References": [
            "https://www.cloudflare.com/en-gb/learning/ssl/why-is-http-not-secure/"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {
            "Resource": "aws_alb_listener.my-alb-listener",
            "Provider": "AWS",
            "Service": "elb",
            "StartLine": 25,
            "EndLine": 25
          }
        },
        {
          "Type": "Terraform Security Check",
          "ID": "AVD-AWS-0081",
          "Title": "AWS Classic resource usage.",
          "Description": "Classic resources are running in a shared environment with other customers",
          "Message": "Classic resources should not be used.",
          "Resolution": "Switch to VPC resources",
          "Severity": "CRITICAL",
          "References": [
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {
            "Resource": "aws_db_security_group.my-group",
            "Provider": "AWS",
            "Service": "rds",
            "StartLine": 28,
            "EndLine": 30
          }
        },
        {
          "Type": "Terraform Security Check",
          "ID": "AVD-AWS-0107",
          "Title": "An ingress security group rule allows traffic from /0.",
          "Description": "Your port exposed to the internet",
          "Message": "Security group rule allows ingress from public internet.",
          "Resolution": "Set a more restrictive cidr range",
          "Severity": "CRITICAL",
          "References": [
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {
            "Resource": "aws_security_group_rule.my-rule",
            "Provider": "AWS",
            "Service": "vpc",
            "StartLine": 20,
            "EndLine": 20
          }
        },
        {
          "Type": "Terraform Security Check",
          "ID": "AVD-AWS-0124",
          "Title": "Missing description for security group rule.",
          "Description": "Descriptions provide context for the firewall rule reasons",
          "Message": "Security group rule does not have a description.",
          "Resolution": "Add descriptions for all security groups rules",
          "Severity": "LOW",
          "References": [
            "https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {
            "Resource": "aws_security_group_rule.my-rule",
            "Provider": "AWS",
            "Service": "vpc",
            "StartLine": 18,
            "EndLine": 21
          }
        },
        {
          "Type": "Terraform Security Check",
          "ID": "AVD-AZU-0038",
          "Title": "Enable disk encryption on managed disk",
          "Description": "Data could be read if compromised",
          "Message": "Managed disk is not encrypted.",
          "Resolution": "Enable encryption on managed disks",
          "Severity": "HIGH",
          "References": [
            "https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {
            "Resource": "azurerm_managed_disk.source",
            "Provider": "Azure",
            "Service": "compute",
            "StartLine": 34,
            "EndLine": 34
          }
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/api.Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 20,
        "Failures": 3,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS001",
          "Title": "':latest' tag used",
          "Description": "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.",
          "Message": "Specify a tag in the 'FROM' statement for image 'golang'",
          "Namespace": "appshield.dockerfile.DS001",
          "Query": "data.appshield.dockerfile.DS001.deny",
          "Resolution": "Add a tag to the image in the 'FROM' statement",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds001",
          "References": [
            "https://avd.aquasec.com/appshield/ds001"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS005",
          "Title": "ADD instead of COPY",
          "Description": "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
          "Message": "Consider using 'COPY . /go/src/github.com/ZupIT/horus' command instead of 'ADD . /go/src/github.com/ZupIT/horus'",
          "Namespace": "appshield.dockerfile.DS005",
          "Query": "data.appshield.dockerfile.DS005.deny",
          "Resolution": "Use COPY instead of ADD",
          "Severity": "LOW",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds005",
          "References": [
            "https://docs.docker.com/engine/reference/builder/#add",
            "https://avd.aquasec.com/appshield/ds005"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/bandit/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 22,
        "Failures": 1,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/brakeman/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 22,
        "Failures": 1,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/db.Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 21,
        "Failures": 2,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS005",
          "Title": "ADD instead of COPY",
          "Description": "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
          "Message": "Consider using 'COPY deployments/mongo-init.js /docker-entrypoint-initdb.d/' command instead of 'ADD deployments/mongo-init.js /docker-entrypoint-initdb.d/'",
          "Namespace": "appshield.dockerfile.DS005",
          "Query": "data.appshield.dockerfile.DS005.deny",
          "Resolution": "Use COPY instead of ADD",
          "Severity": "LOW",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds005",
          "References": [
            "https://docs.docker.com/engine/reference/builder/#add",
            "https://avd.aquasec.com/appshield/ds005"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/enry/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 21,
        "Failures": 2,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS013",
          "Title": "'RUN cd ...' to change directory",
          "Description": "Use WORKDIR instead of proliferating instructions like 'RUN cd … \u0026\u0026 do-something', which are hard to read, troubleshoot, and maintain.",
          "Message": "RUN should not be used to change directory: 'git clone https://github.com/src-d/enry.git \u0026\u0026 cd enry \u0026\u0026 make build'. Use 'WORKDIR' statement instead.",
          "Namespace": "appshield.dockerfile.DS013",
          "Query": "data.appshield.dockerfile.DS013.deny",
          "Resolution": "Use WORKDIR to change directory",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds013",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
            "https://avd.aquasec.com/appshield/ds013"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/gitauthors/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 22,
        "Failures": 1,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/gitleaks/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 21,
        "Failures": 2,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS001",
          "Title": "':latest' tag used",
          "Description": "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.",
          "Message": "Specify a tag in the 'FROM' statement for image 'zricethezav/gitleaks'",
          "Namespace": "appshield.dockerfile.DS001",
          "Query": "data.appshield.dockerfile.DS001.deny",
          "Resolution": "Add a tag to the image in the 'FROM' statement",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds001",
          "References": [
            "https://avd.aquasec.com/appshield/ds001"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/gosec/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 21,
        "Failures": 2,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS001",
          "Title": "':latest' tag used",
          "Description": "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.",
          "Message": "Specify a tag in the 'FROM' statement for image 'securego/gosec'",
          "Namespace": "appshield.dockerfile.DS001",
          "Query": "data.appshield.dockerfile.DS001.deny",
          "Resolution": "Add a tag to the image in the 'FROM' statement",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds001",
          "References": [
            "https://avd.aquasec.com/appshield/ds001"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/npmaudit/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 22,
        "Failures": 1,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/safety/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 22,
        "Failures": 1,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    },
    {
      "Target": "../../../../../../../examples/leaks/example1/deployments/dockerfiles/spotbugs/Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "MisconfSummary": {
        "Successes": 20,
        "Failures": 3,
        "Exceptions": 0
      },
      "Misconfigurations": [
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS002",
          "Title": "root user",
          "Description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
          "Message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
          "Namespace": "appshield.dockerfile.DS002",
          "Query": "data.appshield.dockerfile.DS002.deny",
          "Resolution": "Add 'USER \u003cnon root user name\u003e' line to the Dockerfile",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds002",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
            "https://avd.aquasec.com/appshield/ds002"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS013",
          "Title": "'RUN cd ...' to change directory",
          "Description": "Use WORKDIR instead of proliferating instructions like 'RUN cd … \u0026\u0026 do-something', which are hard to read, troubleshoot, and maintain.",
          "Message": "RUN should not be used to change directory: 'mkdir -p /usr/share/maven /usr/share/maven/ref   \u0026\u0026 curl -fsSL -o /tmp/apache-maven.tar.gz https://apache.osuosl.org/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz   \u0026\u0026 tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1   \u0026\u0026 rm -f /tmp/apache-maven.tar.gz   \u0026\u0026 ln -s /usr/share/maven/bin/mvn /usr/bin/mvn   \u0026\u0026 mkdir -p /opt   \u0026\u0026 cd /opt   \u0026\u0026 wget -nc -O gradle.zip https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip   \u0026\u0026 unzip gradle.zip   \u0026\u0026 rm -f gradle.zip   \u0026\u0026 mv gradle-${GRADLE_VERSION} gradle   \u0026\u0026 wget -nc -O spotbugs.zip http://repo.maven.apache.org/maven2/com/github/spotbugs/spotbugs/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.zip   \u0026\u0026 unzip spotbugs.zip   \u0026\u0026 rm -f spotbugs.zip   \u0026\u0026 mv spotbugs-${SPOTBUGS_VERSION} spotbugs   \u0026\u0026 wget -nc -O findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar https://repo1.maven.org/maven2/com/h3xstream/findsecbugs/findsecbugs-plugin/${FINDSECBUGS_VERSION}/findsecbugs-plugin-${FINDSECBUGS_VERSION}.jar   \u0026\u0026 echo -n $SPOTBUGS_VERSION \u003e /opt/spotbugs/version'. Use 'WORKDIR' statement instead.",
          "Namespace": "appshield.dockerfile.DS013",
          "Query": "data.appshield.dockerfile.DS013.deny",
          "Resolution": "Use WORKDIR to change directory",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds013",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
            "https://avd.aquasec.com/appshield/ds013"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        },
        {
          "Type": "Dockerfile Security Check",
          "ID": "DS014",
          "Title": "RUN using 'wget' and 'curl'",
          "Description": "Avoid using both 'wget' and 'curl' since these tools have the same effect.",
          "Message": "Shouldn't use both curl and wget",
          "Namespace": "appshield.dockerfile.DS014",
          "Query": "data.appshield.dockerfile.DS014.deny",
          "Resolution": "Pick one util, either 'wget' or 'curl'",
          "Severity": "LOW",
          "PrimaryURL": "https://avd.aquasec.com/appshield/ds014",
          "References": [
            "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
            "https://avd.aquasec.com/appshield/ds014"
          ],
          "Status": "FAIL",
          "Layer": {},
          "IacMetadata": {}
        }
      ]
    }
  ]
}
`
