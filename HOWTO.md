# How to

Here you can find how to add *Horusec* new features.

## Adding new tool using Horusec-engine

#### 1 - Creating engine rules

To begin, you will need to create the rules that you want our engine to run.
These rules are basically one or more regexes that detect a vulnerability.

These regexes have a type, which are:

| Type            | Description                                                                                                                                                                                                                                                     |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| 
| OrMatch         | These are more comprehensive rules, which may have more than one pattern to manifest, hence the name, since our engine will perform the logical OR operation for each of the registered RegExps.                                                                |
| Regular         | It is very similar to OrMatch, but the idea is that it contains multiple ways to detect the same pattern.                                                                                                                                                       |  
| AndMatch        | These are rules that need the file to manifest multiple patterns to be considered something to be reported, therefore, the engine performs the logical operation in each of the registered RegExps to ensure that all conditions have been met.                 |  

Some examples of these rules can be found in the following path separated by language and type:

```
 -horusec
 --development-kit
 ---pkg
 ----engines
```

#### 2 - Creating formatter

After creation, now we only need to call the engine passing the rules and format the result to the horusec standard.

For this, it will be necessary to create a formatter as in the following example:

```
type Formatter struct {
	formatters.IService
	java.Interface
}

func NewFormatter(service formatters.IService) formatters.IFormatter {
	return &Formatter{
		service,
		java.NewRules(),
	}
}

func (f *Formatter) StartAnalysis(projectSubPath string) {
	if f.ToolIsToIgnore(tools.HorusecJava) {
		logger.LogDebugWithLevel(messages.MsgDebugToolIgnored + tools.HorusecJava.ToString())
		return
	}

	f.SetAnalysisError(f.execEngineAndParseResults(projectSubPath), tools.HorusecJava, projectSubPath)
	f.LogDebugWithReplace(messages.MsgDebugToolFinishAnalysis, tools.HorusecJava)
	f.SetToolFinishedAnalysis()
}

func (f *Formatter) execEngineAndParseResults(projectSubPath string) error {
	f.LogDebugWithReplace(messages.MsgDebugToolStartAnalysis, tools.HorusecJava)

	findings, err := f.execEngineAnalysis(projectSubPath)
	if err != nil {
		return err
	}

	return f.ParseFindingsToVulnerabilities(findings, tools.HorusecJava, languages.Java)
}

func (f *Formatter) execEngineAnalysis(projectSubPath string) ([]engine.Finding, error) {
	textUnit, err := f.GetTextUnitByRulesExt(f.GetProjectPathWithWorkdir(projectSubPath))
	if err != nil {
		return nil, err
	}

	allRules := append(f.GetAllRules(), f.GetCustomRulesByTool(tools.HorusecJava)...)
	return engine.RunMaxUnitsByAnalysis(textUnit, allRules, engineenums.DefaultMaxUnitsPerAnalysis), nil
}
```

This example can be found in the following path:

```
 -horusec
 --horusec-cli
 ---internal
 ----services
 -----fomatters
 ------java
 -------horusecjava
 --------fomatter.go
```

It will be necessary to change the enum of tools and language, as well as import the rules created and pass as an argument of the function `RunMaxUnitsByAnalysis`

#### 3 - Calling our formatter

To finish we need to call our formatter that will perform the analysis.

In the following path you will find a file with the name `analyser.go`.
```
 -horusec
 --horusec-cli
 ---internal
 ----controllers
 -----analyser
 ------analyser.go
```

In this file it will be necessary to create a function like the following:

```
func (a *Analyser) detectVulnerabilityDart(projectSubPath string) {
a.monitor.AddProcess(1)
go horusecDart.NewFormatter(a.formatterService).StartAnalysis(projectSubPath)
}
```

Basically we are adding a new process in our `a.monitor.AddProcess(1)` counter, so that horusec is able to wait for all processes to finish.
To finish we call the formatters that we created through the functions `NewFormatter(a.formatterService).StartAnalysis(projectSubPath)`.

Once these steps are finished, just run and test your analysis.

## Adding Security Tool
 
Horusec works as a centralized analysis tool, using different vulnerability scans. So if you want, you can also add one of your interest.
 
To do this, follow the steps below:
 
#### 1 - Creating Docker Image
 
Here at horusec we use the docker to run the analysis tools, avoiding configuration and environment problems.
So all tools used have their respective docker images.

This image must have the desired tool installed.
We recommend that the output of this container be as clean as possible, or a json with the vulnerabilities found.

These images are separated by language, for example `horuszup/horusec-go`.

If the tool you that you want to add is from a language which the horusec already has the image, you only need to add it to the existing dockerfile.

Following is an example of a dockerfile:
 
```
FROM python:alpine

RUN pip install flawfinder
```
 
The image must contain only what is necessary, so that it does not get too big.
 
#### 2 - Creating Formatter and Config
 
For each image of the docker it is necessary it also has a configuration file and what we call a formatter.
 
The formatter is the code responsible for getting the container output and transforming it into the horusec standard object,
adding the workdir configuration, getting the commit author and some other things.

The config file contains the commands that will be executed inside the container to analyze the code.

Following is an example of a container config:
 
```
const CMD = `
		{{WORK_DIR}}
		flawfinder --minlevel 0 --columns --singleline --dataonly --context --csv . > /tmp/result-ANALYSISID.csv
		cat /tmp/result-ANALYSISID.csv
  `
```
It is necessary that the code that will be executed in the container has a `{{WORK_DIR}}` at the beginning. We will replace this section for a specific path of the project that is being analyzed if the user wishes.

Now let's create the code that will read the container's output and parse the standard horusec format.
 
All formatters must follow the standard and implement the interface `IFormatter` in the `interface.go` file.
An example can be found by in the following path:
 
```
 -horusec
 --horusec-cli
 ---internal
 ----services
 -----fomatters
 -----interface.go
 ------c
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

It will also be necessary to add the new image to the image enum, this can be found at:

```
 -horusec
 --horusec-cli
 ---internal
 ----enums
 -----images
 -----images.go
```

As stated earlier, if it is a language that horusec already supports, it will not be necessary to add a new image.

Finally, add the new one to the tool name in the tool's enum.
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

Be careful not to forget that these functions must be performed in go routines, and for each new go routine, it is necessary to update the monitor, as in the previous example, passing the total of new calls. 
In case you forget this step the horusec will finish before the tool finishes.

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

It's ready. Now horusec is integrated with the new tool and generating unified reports.

Feel free to send us a pull request and collaborate with the project. We will love it!

## Adding Custom Rules

With Horusec you are able to dynamically add rules that will be executed on our engines.

#### 1 - Horusec Custom Rules Json

In order to run custom Json rules in Horusec you'll have to create a .json having this code pattern below:

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

#### 2 - Explanation of Json attributes

Check the following table to get to know more about each field.

| Field           | Description                                                                                                                                                                            |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| 
| ID              | Random UUID that will be used to identify the vulnerability, your rules should not duplicate this id.                                                                                  |
| Name            | String with the name of the vulnerability.                                                                                                                                             |
| Description     | String with the description of the vulnerability.                                                                                                                                      |
| Severity        | String with the severity of the vulnerability with the possible values: (INFO, UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL).																   |
| Confidence      | String with the confidence of the vulnerability report with the possible values: (LOW, MEDIUM, HIGH).                                                                                  |
| Type            | String with the regex type containing these possible values: (Regular, OrMatch, AndMatch).                                                                                             |
| Tool            | String with the tool where the rules is going to run containing these possible values: (HorusecCsharp, HorusecJava, HorusecKotlin, HorusecKubernetes, HorusecLeaks, HorusecNodejs).    |
| Expressions     | Array of string containing all the regex that will detect the vulnerability.                                                                                                           |

#### 3 - Regex Types

Our engine works with three types of regex.

| Type            | Description                                                                                                                                                                                                                                                     |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| 
| OrMatch         | These are more comprehensive rules, which may have more than one pattern to manifest, hence the name, since our engine will perform the logical OR operation for each of the registered RegExps.                                                                |
| Regular         | It is very similar to OrMatch, but the idea is that it contains multiple ways to detect the same pattern.                                                                                                                                                       |  
| AndMatch        | These are rules that need the file to manifest multiple patterns to be considered something to be reported, therefore, the engine performs the logical operation in each of the registered RegExps to ensure that all conditions have been met.                 |                                                          |

#### 4 - Custom Rules Flag
To start using the rules you've created, apply the -c flag so you can pass the path to your .json file.

`horusec start -c="{path to your horusec custom rules json file}"`
