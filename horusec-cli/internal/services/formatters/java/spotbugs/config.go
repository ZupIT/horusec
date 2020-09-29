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

const (
	ImageName = "horuszup/spotbugs"
	ImageTag  = "v1.0.1"
	// nolint
	ImageCmd = `
		cd ../../../
		cp -r src tmp
		cd tmp/src
		{{WORK_DIR}}
       if [ -f "pom.xml" ]; then
           project_type=$(cat pom.xml|grep packaging|cut -d'<' -f2|cut -d'>' -f2)
           bash /usr/local/bin/mvn-entrypoint.sh 2> /tmp/errorMavenBuild 1> /dev/null
           if [ $? -eq 0 ]; then
               if [[ "$project_type" = "war" ]]; then
                  # WAR
                   war_file=$(ls -lS target/*.war|head -n1|cut -d'/' -f2|sed -e "s/.war//")
                   mv target/$war_file /tmp/needToBeScanned-ANALYSISID
               else
                  # JAR
                   mkdir /tmp/needToBeScanned-ANALYSISID
                   cp target/*.jar /tmp/needToBeScanned-ANALYSISID/
               fi
               java -jar /opt/spotbugs/spotbugs-4.1.1/lib/spotbugs.jar -textui -quiet -xml -bugCategories SECURITY -exclude /opt/spotbugs/exclude.xml -pluginList /opt/findsecbugs-plugin-1.10.1.jar /tmp/needToBeScanned-ANALYSISID
           else
               echo "ERROR_RUNNING_MAVEN_BUILD"
               cat /tmp/errorMavenBuild
           fi
       elif [ -f "build.gradle" ]; then
           /opt/gradle/bin/gradle build 2> /tmp/errorGradleBuild 1> /dev/null
            if [ $? -eq 0 ]; then
               	mv build /tmp/needToBeScanned-ANALYSISID
               	java -jar /opt/spotbugs/spotbugs-4.1.1/lib/spotbugs.jar -textui -quiet -xml -bugCategories SECURITY -exclude /opt/spotbugs/exclude.xml -pluginList /opt/findsecbugs-plugin-1.10.1.jar /tmp/needToBeScanned-ANALYSISID
            else
               	echo "ERROR_RUNNING_GRADLE_BUILD"
               	cat /tmp/errorGradleBuild
            fi
       else
           echo "ERROR_UNSUPPORTED_JAVA_PROJECT"
       fi
	   chmod -R 777 .
  `
)
