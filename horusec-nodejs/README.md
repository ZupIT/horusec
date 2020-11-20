# HORUSEC-NODEJS-CLI
This is a Command Line Interface to make it search vulnerabilities in JavaScript and TypeScript projects.
To learn more about the structure of this service you can see more in this <a href="../assets/horusec-analysis-cli.jpg">/assets/horusec-analysis-cli.jpg</a>.

## Using with docker
To use with docker you can running this example:
```bash
    LOCAL_PROJECT_PATH="$(pwd)/horusec-nodejs/examples"; \
    docker run --rm \
        -v $LOCAL_PROJECT_PATH:/src \
        horuszup/horusec-nodejs:latest \
        /bin/sh -c "horusec-nodejs run -p /src -o /tmp/output.json && cat /tmp/output.json"
```

## Using locally
To use locally is necessary clone horusec in your local machine and run:
```bash
make build-install-nodejs-cli
```

#### Check the installation
```bash
horusec-nodejs version
```

## Commands
The available commands to usage are:

| Command | Description |
|---------|-------------|
| run     | This command start analysis with default values and in your current directory |
| version | You see actual version running in your local machine |

### Using Flags
You can pass some flags and change their values, for example:
```bash
horusec-nodejs --help
```

All available flags are:

| Flag Flag        | Flag shortcut | Default Value        | Description |
|------------------|---------------|----------------------|-------------|
| log-level        | l             | info                 | This setting will define what level of logging I want to see. The available levels are: "panic","fatal","error","warn","info","debug","trace" |
| json-output-file | o             | output.json          | Name of the json file to save result of the analysis |
| project-path     | p             | ${CURRENT_DIRECTORY} | This setting is to know if I want to change the analysis directory and do not want to run in the current directory. If this value is not passed, Horusec will ask if you want to run the analysis in the current directory. If you pass it it will start the analysis in the directory informed by you without asking anything. |

## Output
When you run analysis you receive this example of output
```json
[
  {
    "ID": "a35afa4b-7fbd-4872-9fe9-c78243f76c9c",
    "Name": "No use weak random number generator",
    "Severity": "HIGH",
    "MEDIUM": "MEDIUM",
    "CodeSample": "\"price\": parseInt(Math.random() * 100),",
    "Description": "When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information. As the Math.random() function relies on a weak pseudorandom number generator, this function should not be used for security-critical applications or for protecting sensitive data. In such context, a cryptographically strong pseudorandom number generator (CSPRNG) should be used instead. For more information checkout the CWE-338 (https://cwe.mitre.org/data/definitions/338.html) advisory.",
    "SourceLocation": {
      "Filename": "/src/nodejs-generic-vuln/dummy.js",
      "Line": 20,
      "Column": 24
    }
  }
]
```

## How add more rules?
To add new rules it is necessary to understand the structure of this CLI. When we start the CLI we use a base called [cli_standard](/development-kit/pkg/cli_standard) its goal is to have the initial commands and call the controller to the CLI in this example is the package [analysis](/development-kit/pkg/engines/nodejs/analysis), this package will call its [rules](/development-kit/pkg/engines/nodejs/analysis) which in turn triggers all the rules that it considers necessary for this CLI.
### Rules
The rules added in horusec-nodejs are grouped in two places in this project which are::
* Rules specific to [.js|.ts|.jsx|.tsx languages](/development-kit/pkg/enums/engine/advisories/nodejs)

All rules follow a flow subdivided between the types:
* `And`
    * The purpose of these rules would be `if all the rules exist in the analyzed file, it will be charged`. 
* `Or`
    * The purpose of these rules would be `if any rule exists in the analyzed file, it will be charged`
* `Regular`
    * The purpose of these rules would be `if any rules exist in the analyzed file and have exactly what is expected, it will be charged`  

### Example adding more rules in C# Language
To exemplify the process of how to add a new rule is quite simple. First you must create a new constructor with a very descriptive name in the file you want and started with the text `NewCsharp + TypeRule + Name` example `NewCsharpRegularWeakHashingFunctionMd5OrSha1`, this new constructor will return a [text.TextRule](https://github.com/ZupIT/horusec-engine/text), then you will return it and add the new constructor to the list of rules that will be executed in the file [csharp.go](/development-kit/pkg/enums/engine/advisories/csharp/csharp.go).

In this builder's content add:
```text
    Metadata.ID: "text type field preferred a UUID v4"
    Metadata.Name: "descriptive name of the vulnerability"
    Metadata.Description: "brief description of the vulnerability and if possible add a reference to the CWE that it fits"
    Metadata.Severity: "using the severity enum rate how critical this vulnerability is"
    Metadata.Confidence: "using the confidence enum classify how assertive this vulnerability is"
    Type: "classify the type of this vulnerability according to the package"
    Expressions: "List of regular expressions you want to add if the vulnerability exists in the analyzed file"
```

`regular.go`
```go
...
func NewNodeJSRegularNoUseWeakRandom() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "a35afa4b-7fbd-4872-9fe9-c78243f76c9c",
			Name:        "No use weak random number generator",
			Description: "When software generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information. As the Math.random() function relies on a weak pseudorandom number generator, this function should not be used for security-critical applications or for protecting sensitive data. In such context, a cryptographically strong pseudorandom number generator (CSPRNG) should be used instead. For more information checkout the CWE-338 (https://cwe.mitre.org/data/definitions/338.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Medium.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`Math\.random\(`),
		},
	}
}

```

`nodejs.go`
```go
...
func AllRulesNodeJSRegular() []text.TextRule {
    return []text.TextRule{
        ...
        regular.NewNodeJSRegularNoUseWeakRandom(),
    }
}
...
```

Finally check if all tests have passed and if possible add a unit test within [nodejs_test.go](/development-kit/pkg/enums/engine/advisories/nodejs/nodejs_test.go) exemplifying the scenario that this new rule would apply.
