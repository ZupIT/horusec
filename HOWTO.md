# How to

Here you can find how to add *Horusec* new features.

## Adding new tool using Horusec-engine

To add a new analyse tool into horusec-cli you should follow the step-by-step examples above:


#### 1 - Create a new CLI by copying some one of the existed one and rename it to **horusec-{name-of-the-cli}**.


e.g.:

[horusec-java](/horusec-java)

[horusec-kotlin](/horusec-kotlin)

[horusec-leaks](/horusec-leakse)


#### 2-  Create the rules to be used by the new CLI that you create before.

e.g.:

[examples](/development-kit/pkg/engines/examples)


#### 3 - Update your CLI to use the rules that you create and update the CLI configuration.

e.g.: Replace the curle braces in the code with your new cli definitions.

```go
// horusec-{name-of-the-cli}/cmd/app/main.go
package main

import (
	"os"

	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/cmd"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/cmd/run"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/cmd/version"
	"github.com/ZupIT/horusec/development-kit/pkg/cli_standard/config"
	"github.com/ZupIT/horusec/development-kit/pkg/engines/{THE-NAME-OF-THE-YOUR-ENGINE-RULES}/analysis" 
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "horusec-{THE-NAME-OF-YOUR-CLI}",
	Short: "Horusec-{THE-NAME-OF-YOUR-CLI} CLI",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger.LogPrint("Horusec Java Command Line Interface")
		return cmd.Help()
	},
	Example: `horusec-{THE-NAME-OF-YOUR-CLI} run`,
}

var configs *config.Config

// nolint
func init() {
	configs = config.NewConfig()
	cmd.InitFlags(configs, rootCmd)
}

func main() {
	controller := analysis.NewAnalysis(configs)
	rootCmd.AddCommand(run.NewRunCommand(configs, controller).CreateCobraCmd())
	rootCmd.AddCommand(version.NewVersionCommand().CreateCobraCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}

```


#### 4 - Update the dockerfile following the example

e.g.: [horusec-java dockerfile](/horusec-java/deployments/Dockerfile)


#### 5 - Create a new formatter into horusec-cli following this [doc](/horusec-cli/README.md)


## Adding Security Tool
 
Horusec works as a centralized analysis tool, using different vulnerability scans. So if you want, you can also add one of your interest.
 
To do this, follow the steps below:
 
#### 1 - Creating Docker Image
 
Here at horusec we use the docker to run the analysis tools, avoiding configuration and environment problems.
So all tools used have their respective docker images.
 
 
This image must have the desired tool installed.
We recommend that the output of this container be as clean as possible, or a json with the vulnerabilities found.
 
Following is an example of a dockerfile:
 
```
 FROM golang:1.14-alpine
  
 RUN apk update && apk upgrade \
  	&& apk add jq curl
  
 RUN set -o pipefail && curl https://api.github.com/repos/liamg/tfsec/releases/latest | jq -r ".assets[] | select(.name | contains(\"tfsec-linux-amd64\")) | .browser_download_url" | xargs wget
  
 RUN mv tfsec-linux-amd64 /bin/tfsec
  
 RUN chmod +x /bin/tfsec
  
 CMD ["/bin/sh"]
```
 
The image must contain only what is necessary, so that it does not get too big.
 
#### 2 - Creating Formatter and Config
 
For each image of the docker it is necessary it also has a configuration file and what we call a formatter.
 
The formatter is the code responsible for getting the container output and transforming it into the horusec standard object,
adding the workdir configuration, getting the commit author and some other things.

The config file must contain the name and tag of the docker image that will be executed, which must be in the local docker or dockerhub.
It must also contain all the commands that will be executed inside the container to analyze the code.
 
 
Following is an example of a container config:
 
```
 const (
    	ImageName = "horusec/tfsec"
    	ImageTag  = "v1.0.0"
    	ImageCmd       = `
    			{{WORK_DIR}}
            	tfsec --format=json | grep -v "WARNING: skipped" > results.json
    			cat results.json
      `
    )
```
 
Now let's create the code that will read the container's output and parse the standard horusec format.
 
All formatters must follow the standard and implement the interface in the interface.go file.
An example can be found by following the following path:
 
```
 -horusec
 --horusec-cli
 ---internal
 ----services
 -----fomatters
 -----interface.go
 ------hcl
 -------fomatter.go
```
 
#### 3 - Updating Enums

You will also need to add the new one to the tool name in the tool's enum. 
If it is a language that is not yet supported, it will also be necessary to add it to the enum of languages.
 
Both can be found in the following path:

```
 -horusec
 --development-kit
 ---pkg
 ----enums
 -----tools
 -----languages
```

#### 4 - Calling Formatter

After completing the formatter implementation, you must call the function in the analyzer controller.

Can be found in the following path:

```
 -horusec
 --horusec-cli
 ---internal
 ----controller
 -----analyser
 ------analyser.go
```

If it is a new language, it will be necessary to create a new function similar to this:

```
 func (a *Analyser) detectVulnerabilityHCL(projectSubPath string) {
 	 a.monitor.AddProcess(1)
 	 go hcl.NewFormatter(a.formatterService).StartHCLTfSec(projectSubPath)
 }
```

You will also need to add the new language to the map contained in the "mapDetectVulnerabilityByLanguage" function.

Here is an example:

```
 func (a *Analyser) mapDetectVulnerabilityByLanguage() map[languages.Language]func(string) {
	 return map[languages.Language]func(string){
          ...
	 	 languages.HCL:        a.detectVulnerabilityHCL,
	 }
 }
```

If it is an existing language, just add the call to the new formatter in the respective existing "detectVulnerability" function.

Before:

```
 func (a *Analyser) detectVulnerabilityJavascript(projectSubPath string) {
	 a.monitor.AddProcess(1)
	 go yarnaudit.NewFormatter(a.formatterService).StartJavascriptYarnAudit(projectSubPath)
 }
```

After:

```
 func (a *Analyser) detectVulnerabilityJavascript(projectSubPath string) {
	 a.monitor.AddProcess(2)
	 go yarnaudit.NewFormatter(a.formatterService).StartJavascriptYarnAudit(projectSubPath)
	 go npmaudit.NewFormatter(a.formatterService).StartJavascriptNpmAudit(projectSubPath)
 }
```

Be careful not to forget that these functions must be performed in go routines, 
and for each new go routine, it is necessary to update the monitor, as in the previous example, passing the total of new calls.
If you forget this step the horusec will finish before the tool finishes analyze.

#### 5 - Updating validations

Finally, it is necessary to update the horusec validations.
When receiving an analysis on the server, we check if the tools and languages sent for the server are valid.

They can be found in the following path:

```
 -horusec
 --development.kit
 ---pkg
 ----usecases
 -----analysis
 ------analysis.go
```

In the analysis.go file look for the "sliceTools" and "sliceLanguages" functions.

Now add the new tool or language to the interface array according to what was added in the enums previously.

#### 6 - Conclusion

And it's ready. Now horusec is inte.grated with the new tool and generating unified reports.

Feel free to send us a pull request and collaborate with the project. We will love it!

## Adding Custom Rules
At Horusec you have the possibility to add rules dynamically that will be executed on our engines.

#### 1 - Horusec Custom Rules Json
To do this it is necessary to create a json file containing the following pattern:

 ```horusec-custom-rules.json
[
   {
      "ID": "0d6c505a-4986-4771-91db-ec4f4ebface7",
      "Name": "Vulnerability name",
      "Description": "Description of the vulnerability",
      "Severity": "Vulnerability severity",
      "Confidence": "Confidence of the vulnerability",
      "Type": "Regex type",
      "Tool": "HorusecCsharp",
      "Expressions": [
         "Regex to respective vulnerability"
      ]
   },
   {
      "ID": "837c504d-38b4-4ea6-987b-d91e92ac86a2",
      "Name": "Cookie Without HttpOnly Flag",
      "Description": "It is recommended to specify the HttpOnly flag to new cookie. For more information access: (https://security-code-scan.github.io/#SCS0009) or (https://cwe.mitre.org/data/definitions/1004.html).",
      "Severity": "LOW",
      "Confidence": "LOW",
      "Type": "OrMatch",
      "Tool": "HorusecCsharp",
      "Expressions": [
         "httpOnlyCookies\s*=\s*['|"]false['|"]",
         "(new\sHttpCookie\(.*\))(.*|\n)*(\.HttpOnly\s*=\s*false)",
         "(new\sHttpCookie)(([^H]|H[^t]|Ht[^t]|Htt[^p]|Http[^O]|HttpO[^n]|HttpOn[^l]|HttpOnl[^y])*)(})"
      ]
   }
]
```

#### 2 - Json Explanation

| Field           | Description                                                                                                                                          |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------| 
| ID              | Random UUID that will be used to identify the vulnerability, your rules should not duplicate this id.                                                |
| Name            | String with the name of the vulnerability.                                                                                                           |
| Description     | String with the description of the vulnerability.                                                                                                    |
| Severity        | String with the severity of the vulnerability with the possible values: (INFO, AUDIT, LOW, MEDIUM, HIGH).                                            |
| Confidence      | String with the confidence of the vulnerability report with the possible values: (LOW, MEDIUM, HIGH).                                                |
| Type            | String with the regex type with the possible values: (Regular, OrMatch, AndMatch).                                                                   |
| Tool            | String with the regex type with the possible values: (HorusecCsharp, HorusecJava, HorusecKotlin, HorusecKubernetes, HorusecLeaks, HorusecNodejs).    |
| Expressions     | Array of string containing all the regex that will detect the vulnerability.                                                                         |

#### 3 - Regex Types

| Type            | Description                                                                                                                                          |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------| 
| OrMatch         | If any regex in the array matches this vulnerability will be reported. Regexes need to be in the context of the same vulnerability.                  |
| Regular         | If any regex in the array matches this vulnerability will be reported. Regexes don't need to be related.                                             |
| AndMatch        | In this type all regexes must match for the vulnerability to be reported.                                                                            |

#### 4 - Custom Rules Flag
To use the rules you created use the `-c` flag passing the path to the json file.

`horusec start -c="{path to your horusec custom rules json file}"`
