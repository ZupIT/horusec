package images

import "github.com/ZupIT/horusec-devkit/pkg/enums/languages"

const (
	DefaultRegistry = "docker.io"
	C               = "horuszup/horusec-c:v1.0.0"
	Csharp          = "horuszup/horusec-csharp:v1.0.0"
	Elixir          = "horuszup/horusec-elixir:v1.0.0"
	Generic         = "horuszup/horusec-generic:v1.0.0"
	Go              = "horuszup/horusec-go:v1.0.0"
	HCL             = "horuszup/horusec-hcl:v1.0.0"
	Javascript      = "horuszup/horusec-js:v1.0.0"
	Leaks           = "horuszup/horusec-leaks:v1.0.1"
	PHP             = "horuszup/horusec-php:v1.0.0"
	Python          = "horuszup/horusec-python:v1.0.0"
	Ruby            = "horuszup/horusec-ruby:v1.0.2"
	Shell           = "horuszup/horusec-shell:v1.0.0"
)

func MapValues() map[languages.Language]string {
	return map[languages.Language]string{
		languages.CSharp:     Csharp,
		languages.Leaks:      Leaks,
		languages.Go:         Go,
		languages.Javascript: Javascript,
		languages.Python:     Python,
		languages.Ruby:       Ruby,
		languages.HCL:        HCL,
		languages.Generic:    Generic,
		languages.PHP:        PHP,
		languages.Elixir:     Elixir,
		languages.Shell:      Shell,
		languages.C:          C,
	}
}
