<a href="https://github.com/ZupIT/horusec/releases"><img src="https://img.shields.io/github/v/tag/ZupIT/horusec?color=green&label=Version"/></a>
<a href="https://github.com/ZupIT/horusec/actions?query=branch%3Amaster+"><img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/e2e/master?label=Build"/></a>
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

<p></p>
<p></p>
<p align="center" margin="20 0"><a href="https://horusec.io/"><img src="assets/horusec_logo.png" alt="logo_header" width="65%" style="max-width:100%;"/></a></p>
<p></p>
<p></p>


## What is Horusec?
Horusec is an open source tool that performs static code analysis to identify security flaws during the development process. Currently, the languages for analysis are: C#, Java, Kotlin, Python, Ruby, Golang, Terraform, Javascript, Typescript, Kubernetes, PHP, C, HTML, JSON, Dart, Elixir, Shell, Nginx. The tool has options to search for key leaks and security flaws in all files of your project, as well as in Git history. Horusec can be used by the developer through the CLI and by the DevSecOps team on CI /CD mats. See in our [DOCUMENTATION](https://horusec.io/docs/overview/) the complete list of tools and languages that we perform analysis

<p align="center" margin="20 0"><img src="assets/horusec-complete-architecture.png" alt="architecture" width="100%" style="max-width:100%;"/></p>

## Example Output

<img src="assets/usage_horusec.gif" alt="usage_gif" width="100%" style="max-width:100%;"/>

## Getting started

### Mac or Linux
```sh
curl -fsSL https://horusec.io/bin/install.sh | bash
```

### Windows
```sh
curl "https://horusec.io/bin/latest/win_x64/horusec.exe" -o "./horusec.exe" && ./horusec.exe version
```

To see more details how install go to <a href="https://horusec.io/docs/cli/installation/">HERE</a>

#### Check the installation
```bash
horusec version
```

## Usage CLI
To use horusec-cli and check the application's vulnerabilities:
```bash
horusec start -p="./"
```

**WARN:** When horusec starts an analysis it creates a folder called `.horusec`. This folder serves as the basis for not changing your code. So we recommend that you add the line `.horusec` into your `.gitignore` file so that this folder does not need to be sent to your git server!


## Usage with Docker
```sh
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/src horuszup/horusec-cli:latest horusec start -p /src -P $(pwd)
```

## Usage with Horusec-Web application
Generate your the authorization token in order to be able to access the report through the web application.
See more about [**Horusec web application here**](https://github.com/ZupIT/horusec-platform)

```bash
horusec start -p="./" -a="<YOUR_TOKEN_AUTHORIZATION>"
```

To acquire the authorization token and be able to analytically check the application's vulnerabilities on our panel, see more details <a href="https://horusec.io/docs/tutorials/how-to-create-an-authorization-token">HERE</a>.

## Usage with Visual Studio Code
You can analysis your project using the Visual Studio Code with Horusec extension.
See [**more details Here**](https://horusec.io/docs/extensions/visual-studio-code/):

## Usage with Pipeline
You can perform an analysis of your project before you hold Deploy in your environment by ensuring maximum security in your organization.
See [**more details Here**](https://horusec.io/docs/cli/installation/#installation-via-pipeline):


## Features
- Safety tools orcherator simultaneously analyzing more than 18 languages with support from other 20 security tools;
- Idependent analysis of your project size;
- Search for their historical git by secrets and other contents exposed;
- Your analysis can be fully configurable, [see all available resources](https://horusec.io/docs/cli/resources/#3-flags);

## Contributing

Read our [contributing guide](CONTRIBUTING.md) to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes to horusec.

## Communication

We have a few channels for contact, feel free to reach out to us at:

- [GitHub Issues](https://github.com/ZupIT/horusec/issues)

## Contributors

This project exists thanks to all the [contributors]((https://github.com/ZupIT/horusec/graphs/contributors)). You rock!   ❤️🚀

[Semgrep]: https://github.com/returntocorp/semgrep
