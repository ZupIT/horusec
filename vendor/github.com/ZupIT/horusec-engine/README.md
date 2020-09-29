# Horusec Engine

This repository contains the standalone SAST engine used by the Horusec project.

The goal of this project is to provide a baseline functionality and the basic building blocks
for anyone to build their own SAST tool.

## But what is a SAST tool anyway?
A Static Application Security Testing tool is an automated scanner for security issues in your source code or binary artifact
The main goal of it is to identify, as soon as possible in your development lifecycle any possible threat to your infrastructure
and your user's data. One important thing to remember is that no SAST tool found actual vulnerabilities, because the tool never
actually executes the program being analyzed, therefore, you still have to keep testing your applications with more traditional
pentesting and any other tests that you can execute.


## With so many SAST tools out there, why even bother to right my own?
The main benefit you can get for writing your own is the amount of knowledge about your own application you can impress
on your tool. Sure that, in the first months a off-the-shelf tool will have more rules and more corner cases covered than yours
but with the right amount of dedication of improving and expanding the techniques your tool uses, you can easily overcome 
the regular market tools.

## Okay, I decided write my own tool, what does this engine helps me?
Right now the only built-in technique our engine uses is the syntax pattern matching technique, a powerful yet simple technique
to uncover the most common mistakes that you can left in your code base.

But, as I shall show to you, the extensibility of the engine is the main advantage it presents.

All the design around our solution was focused on extensibility and iteroperability of techniques in one single analysis.

To achieve that, we make use of three simple yet very expressive components that can be easily extended to suit your needs
and allows you to expand the functionality of the engine with new techniques, while still having a common ground for all of them.


## The main components

### Unit
The most important of them, an unit is a piece of your code that makes sense to be analyzed as one. So every Unit is
a lexical scope, you can imagine for example, a C++ namespace of a Java Class. The engine will threat all the files and code inside
an unit as one thing, and will only be able to cross reference anything inside a single unit.
We are working on a more profound and complex lexical analysis between units and even a more deeper one inside units, [so any help is welcome!](https://github.com/ZupIT/horusec-engine/issues)

### Rule
This is the only part that the engine won't help you, because you have to provide your own rules. The FOSS version of the Horusec
tool have a lot of rules that you can use, but this interface is here to exactly encourage you to learn more about how security
issues manifest in your favorite language syntax, and therefore how to identify them with your tool.

### Finding
The finding is a key part of your tool, since it's with it that you actually extract useful insight from the source code being analyzed.
The struct right now is focused on simplicity, but we are working to implement it following the SARIF specification, so you can have complete control of where you import your data.


## Examples

A simple analysis of a inmemory string:
```go
	var exampleGoFile = `package version

import (
	"github.com/ZupIT/horusec/development-kit/pkg/utils/logger"
	"github.com/spf13/cobra"
)

type IVersion interface {
	CreateCobraCmd() *cobra.Command
}

type Version struct {
}

func NewVersionCommand() IVersion {
	return &Version{}
}

func (v *Version) CreateCobraCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Short:   "Actual version installed of the horusec",
		Example: "horusec version",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.LogPrint(cmd.Short + " is: ")
			return nil
		},
	}
}
`

	var textUnit TextUnit = TextUnit{}
	goTextFile, err := NewTextFile("example/cmd/version.go", []byte(exampleGoFile))

	if err != nil {
		t.Error(err)
	}

	textUnit.Files = append(textUnit.Files, goTextFile)

	var regularMatchRule TextRule = TextRule{}
	regularMatchRule.Type = Regular
	regularMatchRule.Expressions = append(regularMatchRule.Expressions, regexp.MustCompile(`cmd\.Short`))

	rules := []engine.Rule{regularMatchRule}
	program := []engine.Unit{textUnit}

	findings := engine.Run(program, rules)

	for _, finding := range findings {
		t.Log(finding.SourceLocation)
	}
```