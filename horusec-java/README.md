# HORUSEC-JAVA-CLI
This is a Command Line Interface to make it search vulnerabilities in java project.
To learn more about the structure of this service you can see more in this <a href="../assets/horusec-analysis-cli.jpg">/assets/horusec-analysis-cli.jpg</a>.

## Using with docker
To use with docker you can running this example:
```bash
    LOCAL_PROJECT_PATH="$(pwd)/horusec-java/examples"; \
    docker run --rm \
        -v $LOCAL_PROJECT_PATH:/src \
        horuszup/horusec-java:latest \
        /bin/sh -c "horusec-java run -p /src -o /tmp/output.json && cat /tmp/output.json"
```

## Using locally
To use locally is necessary clone horusec in your local machine and run:
```bash
make build-install-java-cli
```

#### Check the installation
```bash
horusec-java version
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
horusec-java --help
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
    "ID": "3dfb3624-e218-4e2b-a7e9-814b64aaa43e",
    "Name": "HardCodedPassword",
    "Description": "Hardcoded password is an vulnerability",
    "SourceLocation": {
      "Filename": "/src/java-hardcodedpass/src/main/java/com/mycompany/app/App.java",
      "Line": 148,
      "Column": 8
    }
  }
]
```

## How add more rules?
To add new rules it is necessary to understand the structure of this CLI. When we start the CLI we use a base called [cli_standard](/development-kit/pkg/cli_standard) its goal is to have the initial commands and call the controller to the CLI in this example is the package [analysis](/development-kit/pkg/engines/java/analysis), this package will call its [rules](/development-kit/pkg/engines/java/analysis) which in turn triggers all the rules that it considers necessary for this CLI.
### Rules
The rules added in horusec-java are grouped in two places in this project which are::
* Rules specific to [Java language](/development-kit/pkg/enums/engine/advisories/java)
* Generic rules applied to [mobile applications](/development-kit/pkg/enums/engine/advisories/jvm)(JVM call that can be shared)

All rules follow a flow subdivided between the types:
* `And`
    * The purpose of these rules would be `if all the rules exist in the analyzed file, it will be charged`. 
* `Or`
    * The purpose of these rules would be `if any rule exists in the analyzed file, it will be charged`
* `Regular`
    * The purpose of these rules would be `if any rules exist in the analyzed file and have exactly what is expected, it will be charged`  

### Example adding more rules in Java Language
To exemplify the process of how to add a new rule is quite simple. First you must create a new constructor with a very descriptive name in the file you want and started with the text `NewJava + TypeRule + Name` example `NewJavaRegularWeakHash`, this new constructor will return a [text.TextRule](https://github.com/ZupIT/horusec-engine/text), then you will return it and add the new constructor to the list of rules that will be executed in the file [java.go](/development-kit/pkg/enums/engine/advisories/java/java.go).

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
func NewJavaRegularWeakHash() text.TextRule {
	return text.TextRule{
		Metadata: engine.Metadata{
			ID:          "de9be233-8f65-4e2a-bb6e-8acbc2a4dff3",
			Name:        "Weak Cryptographic Hash Function used",
			Description: "Using a weak CHF pose a threat to your application security since it can be vulnerable to a number of attacks that could lead to data leaking, improper access of features and resources of your infrastructure and even rogue sessions. For more information checkout the CWE-327 (https://cwe.mitre.org/data/definitions/327.html) advisory.",
			Severity:    severity.High.ToString(),
			Confidence:  confidence.Low.ToString(),
		},
		Type: text.Regular,
		Expressions: []*regexp.Regexp{
			regexp.MustCompile(`getInstance("md4")|getInstance("rc2")|getInstance("rc4")|getInstance("RC4")|getInstance("RC2")|getInstance("MD4")`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*MD5["|']*\)|MessageDigest\.getInstance\(["|']*md5["|']*\)|DigestUtils\.md5\(`),
			regexp.MustCompile(`MessageDigest\.getInstance\(["|']*SHA-?1["|']*\)|MessageDigest\.getInstance\(["|']*sha-?1["|']*\)|DigestUtils\.sha\(|DigestUtils\.getSha1Digest\(`),
			regexp.MustCompile(`getInstance\(["|']rc4["|']\)|getInstance\(["|']RC4["|']\)|getInstance\(["|']RC2["|']\)|getInstance\(["|']rc2["|']\)`),
			regexp.MustCompile(`getInstance\(["|']md4["|']\)|getInstance\(["|']MD4["|']\)|getInstance\(["|']md2["|']\)|getInstance\(["|']MD2["|']\)`),
		},
	}
}
```

`java.go`
```go
...
func AllRulesJavaRegular() []text.TextRule {
    return []text.TextRule{
        ...
        regular.NewJavaRegularWeakHash(),
    }
}
...
```

If you wish, the same processes can be done for the [JVM type builders' package](/development-kit/pkg/enums/engine/advisories/jvm) too.
Finally check if all tests have passed and if possible add a unit test within [java_test.go](/development-kit/pkg/enums/engine/advisories/java/java_test.go) exemplifying the scenario that this new rule would apply.
