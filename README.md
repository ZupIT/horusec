<p align="center" margin="20 0"><a href="https://horusec.io/">
    <img src="assets/horusec_logo.png" alt="logo_header" width="65%" style="max-width:100%;"/></a></p>

<p align="center">
    <a href="https://github.com/ZupIT/horusec/releases" alt="version">
        <img src="https://img.shields.io/github/v/release/ZupIT/horusec?label=version"/></a>
    <a href="https://github.com/ZupIT/horusec/pulse" alt="activity">
        <img src="https://img.shields.io/github/commit-activity/m/ZupIT/horusec?label=activity"/></a>
    <a href="https://github.com/ZupIT/horusec/graphs/contributors" alt="contributors">
        <img src="https://img.shields.io/github/contributors/ZupIT/horusec?label=contributors"/></a>
    <a href="https://github.com/ZupIT/horusec/actions/workflows/lint.yml" alt="lint">
        <img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/Lint?label=lint"/></a>
    <a href="https://github.com/ZupIT/horusec/actions/workflows/test.yml" alt="test">
        <img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/Test?label=test"/></a>
    <a href="https://github.com/ZupIT/horusec/actions/workflows/security.yml" alt="security">
        <img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/Security?label=security"/></a>
    <a href="https://github.com/ZupIT/horusec/actions/workflows/coverage.yml" alt="coverage">
        <img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/Coverage?label=coverage"/></a>
    <a href="https://opensource.org/licenses/Apache-2.0" alt="license">
        <img src="https://img.shields.io/badge/license-Apache%202-blue"/></a>


## What is Horusec?
Horusec is an open source tool that performs static code analysis to identify security flaws during the development process. Currently, the languages for analysis are: C#, Java, Kotlin, Python, Ruby, Golang, Terraform, Javascript, Typescript, Kubernetes, PHP, C, HTML, JSON, Dart, Elixir, Shell, Nginx. The tool has options to search for key leaks and security flaws in all files of your project, as well as in Git history. Horusec can be used by the developer through the CLI and by the DevSecOps team on CI /CD mats. See in our [DOCUMENTATION](https://horusec.io/docs/overview/) the complete list of tools and languages that we perform analysis

<p align="center" margin="20 0"><img src="assets/horusec-complete-architecture.png" alt="architecture" width="100%" style="max-width:100%;"/></p>

## Example Output

<img src="assets/usage_horusec.gif" alt="usage_gif" width="100%" style="max-width:100%;"/>

## Getting started

### Mac or Linux
```
make install
```

or

```sh
curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/master/deployments/scripts/install.sh | bash -s latest
```

### Windows
```sh
curl "https://github.com/ZupIT/horusec/releases/latest/download/horusec_win_x64.exe" -o "./horusec.exe" && ./horusec.exe version
```

All binaries with versions can be found in our [releases page](https://github.com/ZupIT/horusec/releases).

Click [here](https://horusec.io/docs/cli/installation) to see more details in how to install.

#### Check the installation
```bash
horusec version
```

## Usage CLI
To use horusec-cli and check the application's vulnerabilities:
```bash
horusec start -p .
```

**WARN:** When horusec starts an analysis it creates a folder called `.horusec`. This folder serves as the basis for not changing your code. So we recommend that you add the line `.horusec` into your `.gitignore` file so that this folder does not need to be sent to your git server!


## Usage with Docker
It is also possible to be using the horusec through a docker image `horuszup/horusec-cli:latest.

To do so, just run the following command:
```sh
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/src horuszup/horusec-cli:latest horusec start -p /src -P $(pwd)
```

As you can see in the command, we created a volume containing the project `-v $(pwd):/src`.

With the docker image we ended up having two paths where the project can be found.

The `-p` flag will represent the project path inside the container, in our example `/src`.
The `-P` flag will represent the project outside the container, in our example is represented by `$(pwd)`,
will be also needed to pass the project path to mount the volume `-v $(pwd):/src`.

## Usage with Horusec-Web application
Manage your vulnerabilities through our web interface. With it, you can have a dashboard of metrics about your
vulnerabilities, control of false positives, authorization token, update of vulnerabilities and much more.
See more about it [**here**](https://github.com/ZupIT/horusec-platform).

Usage example sending an analysis to Horusec web services.
```bash
horusec start -p <PATH_TO_YOUR_PROJECT> -a <YOUR_AUTHORIZATION_TOKEN>
```

You can create an authorization token through the horusec manager web service, click
[**here**](https://horusec.io/docs/tutorials/how-to-create-an-authorization-token) to see more details.

## Usage with Visual Studio Code
Analyze your project using the Visual Studio Code with Horusec extension.
See [**more details Here**](https://horusec.io/docs/extensions/visual-studio-code/):

## Usage with Pipeline
You can perform an analysis of your project before you hold Deploy in your environment by ensuring maximum security in your organization.
See [**more details Here**](https://horusec.io/docs/cli/installation/#installation-via-pipeline):

## Features
- Analyzes simultaneously 18 languages with 20 different security tools to increase accuracy;
- Search for their historical git by secrets and other contents exposed;
- Your analysis can be fully configurable, [see all cli available resources](https://horusec.io/docs/cli/resources/#3-flags);

## Contributing

Read our [contributing guide](CONTRIBUTING.md) to learn about our development process, how to propose bugfixes and improvements, and how to build and test your changes to horusec.

## Communication

We have a few channels for contact, feel free to reach out to us at:

- [GitHub Issues](https://github.com/ZupIT/horusec/issues)

## Contributing

Feel free to use, recommend improvements, or contribute to new implementations.

If this is our first repository that you visit, or would like to know more about Horusec,
check out some of our other projects.

- [Horusec Platform](https://github.com/ZupIT/horusec-platform)
- [Horusec DevKit](https://github.com/ZupIT/horusec-devkit)
- [Horusec Engine](https://github.com/ZupIT/horusec-engine)
- [Horusec Operator](https://github.com/ZupIT/horusec-operator)
- [Horusec Admin](https://github.com/ZupIT/horusec-admin)
- [Horusec VsCode](https://github.com/ZupIT/horusec-vscode-plugin)

This project exists thanks to all the contributors. You rock! ❤️🚀
