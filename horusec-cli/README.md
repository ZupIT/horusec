# HORUSEC-CLI
This is a Command Line Interface to make it easier to use horusec services.
Its objective is to find vulnerabilities and errors in projects.
Working as an information centralizer, horusec becomes an orchestrator of security tools by centralizing its outputs in one place, thus facilitating the analytical part of how many security flaws my projects contain, what those flaws are, who made that flaw and even in some cases the best way to correct it.
To learn more about the structure of this service you can see more in this <a href="../assets/horusec-cli.jpg">/assets/horusec-cli.jpg</a>.

## Installing
To install you can follow some steps:

#### - Installing download binary
* Example of link to download binary automatic for `linux` and `mac` in **latest version**
    ```bash
    curl -fsSL https://horusec.io/bin/install.sh | bash
    ```
* Example of link to download binary automatic for `linux` and `mac` in **specific version**
    ```bash
    curl -fsSL https://horusec.io/bin/install.sh | bash -s v1-0-0
    ```
* All versions are enable in:
    * https://horusec.io/bin/all-version-cli.txt
* All operational system enable are:
    * `linux_x86`, `linux_x64`, `mac_x64`, `win_x86`, `win_x64`
* Download binary manually
    * Also Replace your $version and $os
        * https://horusec.io/bin/$version/$os/horusec
    * Example to download the latest version manually to `windows x64`:
        ```bash
        curl "https://horusec.io/bin/latest/win_x64/horusec.exe" -o "./horusec.exe" && ./horusec.exe version
        ```
    * Example to download the latest version manually to `linux x64`:
        ```bash
        curl "https://horusec.io/bin/latest/linux_x64/horusec" -o "./horusec" && chmod +x ./horusec && ./horusec version
        ```
    * Example to download the latest version manually to `mac x64`:
        ```bash
        curl "https://horusec.io/bin/latest/mac_x64/horusec" -o "./horusec" && chmod +x ./horusec && ./horusec version
        ```
##### - Integrate in your pipeline
To integrate horusec in your pipeline also your download binary and run yourself.
* Example using `github actions`
```yaml
name: SecurityPipeline

on: [push]

jobs:
  horusec-security:
    name: horusec-security
    runs-on: ubuntu-latest
    steps:
    - name: Check out code
      uses: actions/checkout@v2
    - name: Running Horusec Security
      run: |
        curl -fsSL https://horusec.io/bin/install.sh | bash
        horusec start -p="./" -e="true"
```

* Example using `jenkins`
```groovy
stages {
        stage('Security') {
            agent {
                docker { image 'docker:dind' }
            }
            steps {
                sh 'curl -fsSL https://horusec.io/bin/install.sh | bash'
                sh 'horusec start -p="./" -e="true"'
            }
        }
    }
```

* Example using `circle-ci`
```yaml
version: 2.1

executors:
  horusec-executor:
    machine:
      image: ubuntu-1604:202004-01

jobs:
  horusec:
    executor: horusec-executor
    steps:
      - checkout
      - run:
          name: Horusec Security Test
          command: |
            curl -fsSL https://horusec.io/bin/install.sh | bash
            horus start -p ./ -e "true"
workflows:
  pipeline:
    jobs:
      - horusec
```

* Example using `code-build`:
    *   Environment:
        - `Managed image`
            - Operational system: `Ubuntu` 
            - Execution time: `Standard`
            - Image: `Any`
            - Image Version: `Latest`
            - Privileged: `true`
            - Allow AWS CodeBuild to modify this service role so it can be used with this build project: `true`

    * Buildspec:
    ```yaml
    version: 0.2
    
    phases:
      install:
        runtime-versions:
            docker: 19
      build:
        commands:
           - docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/src/horusec-vscode horuszup/horusec-cli:latest horusec start -p /src/horusec-vscode -P $(pwd)
    ```

#### Docker image
We also have a docker image for the cli that can be used to replace the binary. Here is an example of use:

`docker run -v /var/run/docker.sock:/var/run/docker.sock -v {path of project in host}:/src/horusec-vscode horuszup/horusec-cli:latest horusec start -p /src/horusec-vscode -P {path of project in host}`
  
We use a bind with the local docker through the volume `-v /var/run/docker.sock:/var/run/docker.sock` (on windows --> `-v //var/run/docker.sock:/var/run/docker.sock`).

A bind type volume it is created to allow the container to access the project `-v path of project in host:/src/horusec-vscode` (`/src/horusec-vscode` --> represents the project path inside the container).

In this case due the docker.sock we need to have the path to the project inside container passed in -p flag, and the original host path in the -P flag.

#### Check the installation
```bash
horusec version
```

## Commands
The available commands to usage are:

| Command | Description |
|---------|-------------|
| start   | This command start analysis with default values and in your current directory |
| version | You see actual version running in your local machine |


## Command Start Options
When we run the start command, there are some settings that can be changed.
The settings can be passed in 3 ways:

* Configuration file
* Environment variables
* Flags

One overwriting the other the flag being the highest level of overwriting

### Using Configuration File
All flags configurations can also be performed through a file called horusec-config.json
(You can see more details about flag configurations at: <a href="#using-flags">HERE</a>).

The configuration file receive an object with the content follow:
```json
{
      "horusecCliHorusecApiUri": "http://0.0.0.0:8000",
      "horusecCliTimeoutInSecondsRequest": 300,
      "horusecCliTimeoutInSecondsAnalysis": 600,
      "horusecCliMonitorRetryInSeconds": 15,
      "horusecCliRepositoryAuthorization": "00000000-0000-0000-0000-000000000000",
      "horusecCliPrintOutputType": "text",
      "horusecCliJsonOutputFilepath": "",
      "horusecCliTypesOfVulnerabilitiesToIgnore": "",
      "horusecCliFilesOrPathsToIgnore": "",
      "horusecCliReturnErrorIfFoundVulnerability": false,
      "horusecCliProjectPath": "",
      "horusecCliFilterPath": "",
      "horusecCliEnableGitHistoryAnalysis": false,
      "horusecCliCertPath": "",
      "horusecCliCertInsecureSkipVerify":  false,
      "horusecCliEnableCommitAuthor": false,
      "horusecCliRepositoryName": "",
      "horusecCliFalsePositiveHashes": "",
      "horusecCliRiskAcceptHashes": "",
      "horusecCliContainerBindProjectPath": "",
      "horusecCliWorkDir": {
	        "go":         [],
	        "csharp":     [],
	        "ruby":       [],
	        "python":     [],
	        "java" :      [],
	        "kotlin":     [],
	        "javaScript": [],
	        "leaks":      [],
            "generic":    [],
            "php":        [],
            "c":          [],
            "yaml":       [],
                "hlc":        []    
      }
}
```

By default, horusec will fetch the configuration file from the directory where horusec start is being executed.
Therefore, it is recommended that you are at the root of your project and that the horusec start command be executed there

### Using Environments Variables
For user Environments Variables to setup how the horusec will run just configure as follows below:
To see more details about this configurations <a href="#using-flags">HERE</a>
```text
export HORUSEC_CLI_HORUSEC_API_URI="http://0.0.0.0:8000"
export HORUSEC_CLI_TIMEOUT_IN_SECONDS_REQUEST="300"
export HORUSEC_CLI_TIMEOUT_IN_SECONDS_ANALYSIS="600"
export HORUSEC_CLI_MONITOR_RETRY_IN_SECONDS="15"
export HORUSEC_CLI_REPOSITORY_AUTHORIZATION="00000000-0000-0000-0000-000000000000"
export HORUSEC_CLI_PRINT_OUTPUT_TYPE="text"
export HORUSEC_CLI_JSON_OUTPUT_FILEPATH=""
export HORUSEC_CLI_TYPES_OF_VULNERABILITIES_TO_IGNORE=""
export HORUSEC_CLI_FILES_OR_PATHS_TO_IGNORE=""
export HORUSEC_CLI_RETURN_ERROR_IF_FOUND_VULNERABILITY="false"
export HORUSEC_CLI_PROJECT_PATH=""
export HORUSEC_CLI_FILTER_PATH=""
export HORUSEC_CLI_ENABLE_GIT_HISTORY_ANALYSIS="false"
export HORUSEC_CLI_CERT_INSECURE_SKIP_VERIFY="false"
export HORUSEC_CLI_CERT_PATH=""
export HORUSEC_CLI_ENABLE_COMMIT_AUTHOR="false"
export HORUSEC_CLI_REPOSITORY_NAME=""
export HORUSEC_CLI_FALSE_POSITIVE_HASHES=""
export HORUSEC_CLI_RISK_ACCEPT_HASHES=""
export HORUSEC_CLI_CONTAINER_BIND_PROJECT_PATH=""
```

### Using Flags
You can pass some flags and change their values, for example:
```bash
horusec start --help
```

All available flags are:

|                  Name                           |  Configuration File Attr                   | Flag name                   | Flag shortcut | Default Value                           | Description                    |
|-------------------------------------------------|--------------------------------------------|-----------------------------|---------------|-----------------------------------------|--------------------------------|
|                                                 |                                            | log-level                   |               | info                                    | This setting will define what level of logging I want to see. The available levels are: "panic","fatal","error","warn","info","debug","trace" |
| HORUSEC_CLI_MONITOR_RETRY_IN_SECONDS            | horusecCliMonitorRetryInSeconds            | monitor-retry-count         | m             | 15                                      | This setting will identify how many in how many seconds. I want to check if my analysis is close to the timeout. The minimum time is 10. |
| HORUSEC_CLI_PRINT_OUTPUT_TYPE                   | horusecCliPrintOutputType                  | output-format               | o             | text                                    | The print output has been change into `json` or `sonarqube` or `text` |
| HORUSEC_CLI_TYPES_OF_VULNERABILITIES_TO_IGNORE  | horusecCliTypesOfVulnerabilitiesToIgnore   | ignore-severity             | s             |                                         | You can specified some type of vulnerabilities to no apply with a error. The types available are: "LOW, MEDIUM, HIGH, AUDIT". Ex.: LOW, AUDIT all vulnerabilities of type configured are ignored |
| HORUSEC_CLI_JSON_OUTPUT_FILEPATH                | horusecCliJsonOutputFilepath               | json-output-file            | O             |                                         | Name of the json file to save result of the analysis Ex.:`./output.json` |
| HORUSEC_CLI_FILES_OR_PATHS_TO_IGNORE            | horusecCliFilesOrPathsToIgnore             | ignore                      | i             |                                         | You can specified some path absolutes of files or folders to ignore in sent to analysis. Ex.: `/home/user/go/project/helpers/ , /home/user/go/project/utils/logger.go, **/*tests.go` This examples all files inside the folder helpers are ignored and the file `logger.go` is ignored too. Is recommended you not send `node_modules`, `vendor`, etc.. folders of dependence of the your project |
| HORUSEC_CLI_HORUSEC_API_URI                     | horusecCliHorusecApiUri                    | horusec-url                 | u             | http://0.0.0.0:8000                     | This setting has the purpose of identifying where the url where the horusec-api service is hosted will be |
| HORUSEC_CLI_TIMEOUT_IN_SECONDS_REQUEST          | horusecCliTimeoutInSecondsRequest          | request-timeout             | r             | 300                                     | This setting will identify how long I want to wait in seconds to send the analysis object to horusec-api. The minimum time is 10. |
| HORUSEC_CLI_TIMEOUT_IN_SECONDS_ANALYSIS         | horusecCliTimeoutInSecondsAnalysis         | analysis-timeout            | t             | 600                                     | This setting will identify how long I want to wait in seconds to carry out an analysis that includes: "acquiring a project", "sending it to analysis", "containers" and "acquiring a response". The minimum time is 10. |
| HORUSEC_CLI_REPOSITORY_AUTHORIZATION            | horusecCliRepositoryAuthorization          | authorization               | a             | 00000000-0000-0000-0000-000000000000    | To run analysis you need of the token of authorization. This token you can getting generating a new token inside of the your repository horusec. See more <a href="#authorization">HERE</a> |
| HORUSEC_CLI_RETURN_ERROR_IF_FOUND_VULNERABILITY | horusecCliReturnErrorIfFoundVulnerability  | return-error                | e             | false                                   | This setting is to know if I want return exit(1) if I find any vulnerability in the analysis |
| HORUSEC_CLI_PROJECT_PATH                        | horusecCliProjectPath                      | project-path                | p             | ${CURRENT_DIRECTORY}                    | This setting is to know if I want to change the analysis directory and do not want to run in the current directory. If this value is not passed, Horusec will ask if you want to run the analysis in the current directory. If you pass it it will start the analysis in the directory informed by you without asking anything. |
| HORUSEC_CLI_CERT_INSECURE_SKIP_VERIFY           | horusecCliCertInsecureSkipVerify           | insecure-skip-verify        | S             | false                                   | This is used to disable certificate validation. Its use is not recommended outside of test cases. |
| HORUSEC_CLI_CERT_PATH                           | horusecCliCertPath                         | certificate-path            | C             |                                         | Used to pass the certificate path. Ex.:`C="/home/example/ca.crt"`.|
| HORUSEC_CLI_FILTER_PATH                         | horusecCliFilterPath                       | filter-path                 | f             |                                         | This setting is to setup the path to run analysis keep current path in your base. |
| HORUSEC_CLI_ENABLE_GIT_HISTORY_ANALYSIS         | horusecCliEnableGitHistoryAnalysis         | enable-git-history          |               | false                                   | This setting is to know if I want enable run gitleaks tools and analysis in all git history searching vulnerabilities. |
| HORUSEC_CLI_ENABLE_COMMIT_AUTHOR                | horusecCliEnableCommitAuthor               | enable-commit-author        | G             | false                                   | Used to enable and disable commit author. Ex.: `G="true"`|
| HORUSEC_CLI_REPOSITORY_NAME                     | horusecCliRepositoryName                   | repository-name             | n             |                                         | Used to send the repository name to the server, must be used together with the company token. |
| HORUSEC_CLI_FALSE_POSITIVE_HASHES               | horusecCliFalsePositiveHashes              | false-positive              | F             |                                         | Used to ignore vulnerability on analysis and setup with type `False positive`. ATTENTION when you add this configuration directly to the CLI, the configuration performed via the Horusec graphical interface will be overwritten. |
| HORUSEC_CLI_RISK_ACCEPT_HASHES                  | horusecCliRiskAcceptHashes                 | risk-accept                 | R             |                                         | Used to ignore vulnerability on analysis and setup with type `Risk accept`. ATTENTION when you add this configuration directly to the CLI, the configuration performed via the Horusec graphical interface will be overwritten. |
| HORUSEC_CLI_TOOLS_TO_IGNORE                     | horusecCliToolsToIgnore                    | tools-ignore                | T             |                                         | Used to ignore tool on run horusec analysis. Available are: GoSec,SecurityCodeScan,Brakeman,Safety,Bandit,NpmAudit,YarnAudit,SpotBugs,HorusecKotlin,HorusecJava,HorusecLeaks,GitLeaks,TfSec,Semgrep,HorusecCsharp,HorusecNodeJS, HorusecKubernetes. Ex.: `T="GoSec, HorusecLeaks"` |
| HORUSEC_CLI_CONTAINER_BIND_PROJECT_PATH         | EnvContainerBindProjectPath                | container-bind-project-path | P             |                                         | Used to pass project path in host when running horusec cli inside a container |
| HORUSEC_CLI_HEADERS                             | horusecCliHeaders                          | headers                     |               |                                         | Used to send dynamic headers on dispatch http request to horusec api service |
|                                                 | horusecCliWorkDir                          |                             |               |                                         | This setting tells to horusec the right directory to run a specific language. |

#### Authorization
For run an analysis is necessary get an token of repository.
Using the web platform **[HORUSEC-MANAGER](http://localhost:8043)** follow there steps bellow you can generate an new token:

- Access the web platform create a new user <a href="../assets/steps-generate-repository-token/step1.png">as the picture shows</a>
- Fill in the required fields <a href="../assets/steps-generate-repository-token/step2.png">as the picture shows</a>
- Fill in the required fields and click register <a href="../assets/steps-generate-repository-token/step3.png">as the picture shows</a>
- **Confirm in your e-mail** the registry and login in system <a href="../assets/steps-generate-repository-token/step4.png">as the picture shows</a>
- Click in add button to add company <a href="../assets/steps-generate-repository-token/step5.png">as the picture shows</a>
- Create an new company <a href="../assets/steps-generate-repository-token/step6.png">as the picture shows</a>
- Select your company <a href="../assets/steps-generate-repository-token/step7.png">as the picture shows</a>
- Go to repositories page <a href="../assets/steps-generate-repository-token/step8.png">as the picture shows</a>
- Click in add button to add repository <a href="../assets/steps-generate-repository-token/step9.png">as the picture shows</a>
- Create an new repository <a href="../assets/steps-generate-repository-token/step10.png">as the picture shows</a>
- Click in tokens buttons to show all tokens of the repository <a href="../assets/steps-generate-repository-token/step11.png">as the picture shows</a>
- Click in add button to add new token <a href="../assets/steps-generate-repository-token/step12.png">as the picture shows</a>
- Fill in the required fields and click save <a href="../assets/steps-generate-repository-token/step13.png">as the picture shows</a>
- Copy or Save the token generated **for use in the horusec-cli** <a href="../assets/steps-generate-repository-token/step14.png">as the picture shows</a>

#### WorkDir
The WorkDir is an representation to run multiple projects inside one directory, that can be configured through the horusec-config.json file.
Let's assume that your project is a C# with .netcore 3.1 app using angular and has the following structure:
```text
|- NetCoreProject/
|--- horusec-config.json
|--- controllers/
|--- NetCoreProject.csproj
|--- views/
|------ pages/
|------ package.json
|------ package-lock.json
```
Because your initial `.csproj` is inside `/NetCoreProject` and your `package-lock` is inside `/NetCoreProject/views`. Then you will need to configure the workdir.
For this example the configuration would be:
```bash
{
    "horusecCliWorkDir": {
        "csharp": [
            "NetCoreProject"
        ],
        "javaScript": [
            "NetCoreProject/views"
        ]
    }
}
```
As you can see, the structure of projects will be divided by language and can support many in each one.

The interface of languages accepts is:
```
{
    go         []string
    csharp     []string
    ruby       []string
    python     []string
    java       []string
    kotlin     []string
    javaScript []string
    leaks      []string
    hlc        []string
    generic    []string
    php        []string
    c          []string
    yaml       []string
}
```

# Example of usage
Example simple
```bash
horusec start
```

Example using other directory. You can see when you pass the flag of projec-path the Horusec not ask for you if the directory is correct.
```bash
horusec start -a="REPOSITORY_TOKEN" -p="/home/user/project" 
```

Example using other directory full flag name
```bash
horusec start --authorization="REPOSITORY_TOKEN" --project-path="/home/user/project" 
```

Example to ignore folders or paths
```bash
horusec start -p="/home/user/project" -a="REPOSITORY_TOKEN" -i="./node_modules,./vendor,./public, **/*test.go"
```

Example to get output json
```bash
horusec start -p="/home/user/project" -a="REPOSITORY_TOKEN" -o="json" -O="./output.json"
```

Example to get output sonarqube
```bash
horusec start -p="/home/user/project" -a="REPOSITORY_TOKEN" -o="sonarqube" -O="./sonarqube.json"
```

## Using
When horusec-cli start a new analysis and YOU DON'T PASS FLAG TO RUN IN THE SPECIFIC PROJECT PATH, you can see it ask for you if the directory informed is correctly.
```bash
✔ The folder selected is: [/home/user/go/src/github.com/ZupIT/horusec]. The Analysis can start in this directory? [Y/n]: Y
```

Press `enter` or type `Y` to accept or `N` to change directory.
By default, it auto-fill for you with a current directory.

Shortly thereafter, you may see some skipped file warn logs. Don't worry this is normal.
By default, we ignore some files of the type:
- All files with extensions:
`".jpg", ".png", ".gif", ".webp", ".tiff", ".psd", ".raw", ".bmp", ".heif", ".indd"
 ".jpeg", ".svg", ".ai", ".eps", ".pdf", ".webm", ".mpg", ".mp2", ".mpeg", ".mpe"
 ".mp4", ".m4p", ".m4v", ".avi", ".wmv", ".mov", ".qt", ".flv", ".swf", ".avchd", ".mpv", ".ogg"`
- IDE folders
- tmp folders and files
- .horusec folder used in the analysis.
- node_modules, vendor folder used by dependence.
- bin folder
```bash
The folder selected is: [/home/user/go/src/github.com/ZupIT/examples]. Proceed? [Y/n]: Y|

WARN[0000] {HORUSEC_CLI} When starting the analysis WE SKIP A TOTAL OF 5 FILES that are not considered to be analyzed. To see more details use flag --log-level=debug 
```

Before the analysis starts it will send your project to `.horusec` folder to not change your code!
```bash
WARN[0000] {HORUSEC_CLI} PLEASE DON'T REMOVE ".horusec" FOLDER BEFORE THE ANALYSIS FINISH! Don’t worry, we’ll remove it after the analysis ends automatically! Project sent to folder in location: [/home/user/go/src/github.com/ZupIT/examples/horus-example-vulnerabilities/.horusec/b490ca3f-9fd9-479f-bcb7-511ad586fafc] 
```

Now you can wait horusec work in your files search vulnerabilities.
```bash
INFO[0000] Hold on! Horusec still analysis your code. Timeout in: 600s
```

If your analysis not contains vulnerabilities you can see an proccess of exit with `success`!
```bash
==================================================================================

HORUSEC ENDED THE ANALYSIS WITH STATUS OF "success" AND WITH THE FOLLOWING RESULTS:

==================================================================================

Analysis StartedAt: 2020-10-15 15:07:30
Analysis FinishedAt: 2020-10-15 15:07:45

==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 27
SecurityTool: HorusecLeaks
Confidence: MEDIUM
File: deployments/certs/client-api-cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Asymmetric Private Key
Found SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.
Type: Vulnerability
ReferenceHash: a777f0cc3ef58361800f8e837ef142bb5b1da23d09c9bd6ad51040e21a46a82d


==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 31
SecurityTool: HorusecLeaks
Confidence: MEDIUM
File: deployments/certs/ca-key.pem
Code: -----BEGIN RSA PRIVATE KEY-----
Details: Asymmetric Private Key
Found SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.
Type: Vulnerability
ReferenceHash: 5f561d3de881caa747d0b465e4d4892e2b7e2798491a3336ff1b2db7feae03a9


==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 27
SecurityTool: HorusecLeaks
Confidence: MEDIUM
File: deployments/certs/ca.pem
Code: -----BEGIN CERTIFICATE-----
Details: Asymmetric Private Key
Found SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.
Type: Vulnerability
ReferenceHash: decf93ed7744547378332b3e4cb5afa73a837a4a5bff968a3a9d1cc9d5e00009


==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 31
SecurityTool: HorusecLeaks
Confidence: MEDIUM
File: deployments/certs/client-api-key.pem
Code: -----BEGIN RSA PRIVATE KEY-----
Details: Asymmetric Private Key
Found SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.
Type: Vulnerability
ReferenceHash: b89ba62ab42e6c9d8d0dfa387e812583a66ea1f8f68b7d9af689bcda1830e1e6


==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 27
SecurityTool: HorusecLeaks
Confidence: MEDIUM
File: deployments/certs/server-cert.pem
Code: -----BEGIN CERTIFICATE-----
Details: Asymmetric Private Key
Found SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.
Type: Vulnerability
ReferenceHash: 178bf5090b749f5eb7b081bccb0112eadac3d9ed3229d813e727ede62a3c6f15


==================================================================================

Language: Leaks
Severity: HIGH
Line: 1
Column: 31
SecurityTool: HorusecLeaks
Confidence: MEDIUM
File: deployments/certs/server-key.pem
Code: -----BEGIN RSA PRIVATE KEY-----
Details: Asymmetric Private Key
Found SSH and/or x.509 Cerficates among the files of your project, make sure you want this kind of information inside your Git repo, since it can be missused by someone with access to any kind of copy.  For more information checkout the CWE-312 (https://cwe.mitre.org/data/definitions/312.html) advisory.
Type: Vulnerability
ReferenceHash: be6d266459bdfb52341fdbd36924dcac6259de0acd91b61b71e7d2335b329d67


==================================================================================

Language: Leaks
Severity: HIGH
Line: 22
Column: 17
SecurityTool: HorusecLeaks
Confidence: HIGH
File: tmp.json
Code: "code": "password = 'thisisnotapassword'",
Details: Hard-coded password
The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.
Type: Vulnerability
ReferenceHash: f385c57fea769b3cab37d5697f245733aa10ba0a4260ac139a9bf0de2075c2d2


==================================================================================

Language: Leaks
Severity: HIGH
Line: 46
Column: 29
SecurityTool: HorusecLeaks
Confidence: HIGH
File: tmp.json
Code: "code": "\"code\": \"password = 'thisisnotapassword' #nohorus\",",
Details: Hard-coded password
The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.
Type: Vulnerability
ReferenceHash: 6d0a3695ca2b381c45a211eec9d7a70698b5ef76c871608591c4f6788395e03f


==================================================================================

Language: Leaks
Severity: HIGH
Line: 70
Column: 41
SecurityTool: HorusecLeaks
Confidence: HIGH
File: tmp.json
Code: 123!'\\n2 \\n3 password = 'thisisnotapassword' #nohorus\\n4 \\n\",",
Details: Hard-coded password
The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.
Type: Vulnerability
ReferenceHash: 95921a4bcbe27cc826c9aeaed1d5888ca4858e10e29a237cb7905bcadd9d3247


==================================================================================

Language: Leaks
Severity: HIGH
Line: 94
Column: 31
SecurityTool: HorusecLeaks
Confidence: HIGH
File: tmp.json
Code: ' #nohorus\\n4 \\n5 command = 'print \\\"this command is not secure!!\\\"'\\n\",",
Details: Hard-coded password
The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.
Type: Vulnerability
ReferenceHash: 3e10e7961d29cc18db5b5fa714c6038ddd767abacaeeec519d1fd7c8bf938412


==================================================================================

Language: Leaks
Severity: HIGH
Line: 142
Column: 29
SecurityTool: HorusecLeaks
Confidence: HIGH
File: tmp.json
Code: "code": "1 secret = 'password123!'\n2 \n3 password = 'thisisnotapassword'\n4 \n",
Details: Hard-coded password
The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.
Type: Vulnerability
ReferenceHash: 234c325a526a25c26eba2ec7e10d7bfd77beb921c6ca68ddadf2b78694addd5f


==================================================================================

Language: Leaks
Severity: HIGH
Line: 166
Column: 23
SecurityTool: HorusecLeaks
Confidence: HIGH
File: tmp.json
Code:  = 'thisisnotapassword' \n4 \n5 command = 'print \"this command is not secure!!\"'\n",
Details: Hard-coded password
The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication to external components, or encryption of internal data. For more information checkout the CWE-798 (https://cwe.mitre.org/data/definitions/798.html) advisory.
Type: Vulnerability
ReferenceHash: 8fcfe8daaac2e7aac63c5447abd2486b8d09d1448a7aca5455c5da33f9091f15


==================================================================================

Language: Go
Severity: MEDIUM
Line: 4
Column: 2
SecurityTool: GoSec
Confidence: HIGH
File: api/util/util.go
Code: 3: import (
4: 	"crypto/md5"
5: 	"fmt"

Details: Blocklisted import crypto/md5: weak cryptographic primitive
Type: Vulnerability
ReferenceHash: 52b41d4a4201cff3da8a5fd6303a97ec5c7ce07e24353b8e94e19daa41ce0a87


==================================================================================

Language: Go
Severity: MEDIUM
Line: 23
Column: 7
SecurityTool: GoSec
Confidence: HIGH
File: api/util/util.go
Code: 22: func GetMD5(s string) string {
23: 	h := md5.New()
24: 	io.WriteString(h, s) // #nohorus

Details: Use of weak cryptographic primitive
Type: Vulnerability
ReferenceHash: ce77f584d135e67bf1b877710b97a9046e4f69b15f940014c346f7f0cc8810aa


==================================================================================

Language: Go
Severity: LOW
Line: 24
Column: 2
SecurityTool: GoSec
Confidence: HIGH
File: api/util/util.go
Code: : 	h := md5.New()
24: 	io.WriteString(h, s) // #nohorus
25: 	md5Result := fmt.Sprintf("%x", h.Sum(ni
Details: Errors unhandled.
Type: Vulnerability
ReferenceHash: 37c571ac9bdead7b161a7b152c320428c5372b0beeaa94d1311649354b4d579f

WARN[0001] {HORUSEC_CLI} When starting the analysis WE SKIP A TOTAL OF 5 FILES that are not considered to be analyzed. To see more details use flag --log-level=debug
==================================================================================

In this analysis, a total of 15 possible vulnerabilities were found and we classified them into:

Total of Vulnerability HIGH is: 12
Total of Vulnerability MEDIUM is: 2
Total of Vulnerability LOW is: 1

==================================================================================


WARN[0015] {HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis 

WARN[0015] [HORUSEC] 15 VULNERABILITIES WERE FOUND IN YOUR CODE SENT TO HORUSEC, SEE MORE DETAILS IN DEBUG LEVEL AND TRY AGAIN
```

Attention if you received a warn of type:
```text
{HORUSEC_CLI} No authorization token was found, your code it is not going to be sent to horusec. Please enter a token with the -a flag to configure and save your analysis 
```
This means that you did not pass the `-a` flag when run `horusec start` and your analysis will not be sent to horusec to be able to analyze the vulnerabilities found. **Don't worry, this is not mandatory.**

After it print the output, if you pass a configuration to return error if found vulnerabilities the horusec will return in your process exit(1) else it's will return exit(0)
