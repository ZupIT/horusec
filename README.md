<a href="https://github.com/ZupIT/horusec/releases"><img src="https://img.shields.io/github/v/tag/ZupIT/horusec?color=green&label=Version"/></a>
<a href="https://github.com/ZupIT/horusec/actions?query=branch%3Amaster+"><img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/e2e/master?label=Build"/></a>
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

<p></p>
<p></p>
<p align="center" margin="20 0"><a href="https://horusec.io/"><img src="assets/horusec_logo.png" alt="logo_header" width="65%" style="max-width:100%;"/></a></p>
<p></p>
<p></p>

> :warning: **We are moving the manager web application to a new repository, see the work in progress**: https://github.com/ZupIT/horusec-platform/tree/develop

## What is Horusec?
Horusec is an open source tool that performs static code analysis to identify security flaws during the development process. Currently, the languages for analysis are: C#, Java, Kotlin, Python, Ruby, Golang, Terraform, Javascript, Typescript, Kubernetes, PHP, C, HTML, JSON, Dart, Elixir, Shell, Nginx. The tool has options to search for key leaks and security flaws in all files of your project, as well as in Git history. Horusec can be used by the developer through the CLI and by the DevSecOps team on CI /CD mats. See in our [DOCUMENTATION](https://horusec.io/docs/overview/) the complete list of tools and languages that we perform analysis

<p align="center" margin="20 0"><img src="assets/horusec-complete-architecture.png" alt="architecture" width="100%" style="max-width:100%;"/></p>

## Getting started

## CLI
To see more details how install go to <a href="https://horusec.io/docs/cli/installation/">HERE</a>

#### Check the installation
```bash
horusec version
```

## Usage
To use horusec-cli and check the application's vulnerabilities:
```bash
horusec start
```

or you can send the authorization token in order to be able to access the report through the web application.

```bash
horusec start -a="<YOUR_TOKEN_AUTHORIZATION>"
```
To acquire the authorization token and be able to analytically check the application's vulnerabilities on our panel, see more details <a href="https://horusec.io/docs/tutorials/how-to-create-an-authorization-token">HERE</a>.


**WARN:** When horusec starts an analysis it creates a folder called `.horusec`. This folder serves as the basis for not changing your code. So we recommend that you add the line `.horusec` into your `.gitignore` file so that this folder does not need to be sent to your git server!

<p align="center" margin="20 0"><img src="assets/usage_horusec.gif" alt="usage_horusec" width="100%" style="max-width:100%;"/></p>

## Web application

### What is it?

Horusec's web application is an extension of the CLI's functionalities that helps to manage and classify the existing vulnerabilities.
* Multitenant application
* Access Control
* Analytical View
* Vulnerabilities classification
* Integration with other oAuth types
* Integration with notification's services
[See more details here](https://horusec.io/docs/web/overview/)
  
## Contributing

Read our [contributing guide](CONTRIBUTING.md) to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes to horusec.

## Communication

We have a few channels for contact, feel free to reach out to us at:

- [GitHub Issues](https://github.com/ZupIT/horusec/issues)

## Contributors

This project exists thanks to all the [contributors]((https://github.com/ZupIT/horusec/graphs/contributors)). You rock!   ❤️🚀

[Semgrep]: https://github.com/returntocorp/semgrep
