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
    <a href="https://github.com/ZupIT/horusec/actions/workflows/e2e.yml" alt="e2e">
        <img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/e2e?label=e2e"/></a>
    <a href="https://github.com/ZupIT/horusec/actions/workflows/build.yaml" alt="build">
        <img src="https://img.shields.io/github/workflow/status/ZupIT/horusec/Build?label=build"/></a>
    <a href="https://opensource.org/licenses/Apache-2.0" alt="license">
        <img src="https://img.shields.io/badge/license-Apache%202-blue"/></a>
    <a href="https://bestpractices.coreinfrastructure.org/projects/5146"><img src="https://bestpractices.coreinfrastructure.org/projects/5146/badge"></a>
</p>

## **Table of contents**
### 1. [**About**](#about)
### 2. [**Getting started**](#getting-started)
>#### 1.1.   [**Requirements**](#requirements)
>#### 1.2.  [**Installation**](#installing-horusec)
### 3. [**Usage**](#usage)
>#### 3.1. [**CLI Usage**](#cli-usage)
>#### 3.2. [**Using Docker**](#using-docker)
>#### 3.3. [**Older versions**](#older-versions)
>#### 3.4. [**Using Horusec-Web application**](#using-horusec-web-application)
>#### 3.5.  [**Using Visual Studio Code**](#using-visual-studio-code)
>#### 3.6. [**Using the Pipeline**](#using-the-pipeline)
### 4. [**Documentation**](#documentation)       
### 5. [**Roadmap**](#roadmap)
### 6. [**Contributing**](#contributing)
### 7. [**Code of Conduct**](#code-of-conduct)
### 8. [**License**](#license)
### 9. [**Community**](#community)



<br>
<br>
<br>

# **About**
Horusec is an open source tool that performs a static code analysis to identify security flaws during the development process. Currently, the languages for analysis are C#, Java, Kotlin, Python, Ruby, Golang, Terraform, Javascript, Typescript, Kubernetes, PHP, C, HTML, JSON, Dart, Elixir, Shell, Nginx. 
The tool has options to search for key leaks and security flaws in all your project's files, as well as in Git history. Horusec can be used by the developer through the CLI and by the DevSecOps team on CI /CD mats. 

Check out our [**Documentation**](https://horusec.io/docs/overview/), you will see the complete list of tools and languages Horusec performs analysis.

<p align="center" margin="20 0"><img src="assets/horusec-complete-architecture.png" alt="architecture" width="100%" style="max-width:100%;"/></p>

### **See an Output example:**

<img src="assets/usage_horusec.gif" alt="usage_gif" width="100%" style="max-width:100%;"/>

# **Getting started**

## **Requirements**

- Docker

You need Docker installed in your machine in order to run Horusec with all the tools we use.
If you don't have Docker, we have a [**flag**](https://horusec.io/docs/cli/resources/#3-flags) `-D true` that will disable the dependency, but it also loses much of the analysis power. 
We recommend using it with Docker.

If you enable commit authors `-G true`, there is also a `git` dependency.

## **Installing Horusec**
### **Mac or Linux**
```
make install
```

or

```sh
curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/master/deployments/scripts/install.sh | bash -s latest
```

### **Windows**
```sh
curl "https://github.com/ZupIT/horusec/releases/latest/download/horusec_win_x64.exe" -o "./horusec.exe" && ./horusec.exe version
```

- You can find all binaries with versions in our [**releases page**](https://github.com/ZupIT/horusec/releases).

- For more details on how to install, check out the [**documentation**](https://horusec.io/docs/cli/installation) 

#### **Check the installation**
```bash
horusec version
```

## **Usage**
### **CLI Usage**
To use horusec-cli and check the application's vulnerabilities, use the following command:
```bash
horusec start -p .
```
> When horusec starts an analysis, it creates a folder called **`.horusec`**. This folder is the basis for not changing your code. We recommend you to add the line **`.horusec`** into your **`.gitignore`** file so that this folder does not need to be sent to your git server.

### **Using Docker**
It is possible to use Horusec through a docker image **`horuszup/horusec-cli:latest`**.

Run the following command to do it:
```sh
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/src horuszup/horusec-cli:latest horusec start -p /src -P $(pwd)
```

- We created a volume containing the project `-v $(pwd):/src`.

With the docker image we ended up having two paths where the project can be found.

The `-p` flag will represent the project path inside the container, in our example `/src`.
The `-P` flag will represent the project outside the container, in our example is represented by `$(pwd)`,
will be also needed to pass the project path to mount the volume `-v $(pwd):/src`.

### **Older versions**

Horusec's v1 is still available.

**WARNING:** The endpoint with v1 will be deprecated, please upgrade your CLI to v2. Check out more details in the [**documentation**](https://horusec.io/docs/migrate-v1-to-v2/). 

### Mac or Linux
``` sh
curl -fsSL https://horusec.io/bin/install.sh | bash -s latest
```

### Windows
```sh
curl "https://horusec.io/bin/latest/win_x64/horusec.exe" -o "./horusec.exe" && ./horusec.exe version
```

- The older binaries can be found at this endpoint, including the latest version of v1 **`v1.10.3`**. 
- As of v2, binaries will no longer be distributed by this endpoint, and you can find in the [**releases page**](https://github.com/ZupIT/horusec/releases).

### **Using Horusec-Web application**
Manage your vulnerabilities through our web interface. You can have a dashboard of metrics about your vulnerabilities, control of false positives, authorization token, update of vulnerabilities and much more.
See the [**web application**](https://github.com/ZupIT/horusec-platform) section to keep reading about it.

Check out the example below, it is sending an analysis to Horusec web services:
```bash
horusec start -p <PATH_TO_YOUR_PROJECT> -a <YOUR_AUTHORIZATION_TOKEN>
```

Check out [**the tutorial on how to create an authorization token through Horusec Manager Web Service**](https://horusec.io/docs/tutorials/how-to-create-an-authorization-token).

**WARNING:** Our web services was moved to a [**new repository**](https://github.com/ZupIT/horusec-platform). You need to upgrade to v2, check out [**how to migrate from v1 to v2**](https://horusec.io/docs/migrate-v1-to-v2).

### **Using Visual Studio Code**
You can analyze your project using Horusec's Visual Studio Code extension.
For more information, [**check out the documentation**](https://horusec.io/docs/extensions/visual-studio-code/).

### **Using the Pipeline**
You can perform an analysis of your project before you hold deployment in your environment by ensuring maximum security in your organization.
For more information, [**check out the documentation**](https://horusec.io/docs/cli/installation/#installation-via-pipeline):

### **Features**
See below: 
- Analyzes simultaneously 18 languages with 20 different security tools to increase accuracy;
- Search for their historical git by secrets and other contents exposed;
- Your analysis can be fully configurable, [**see all CLI available resources**](https://horusec.io/docs/cli/resources/#3-flags).

## **Documentation**
You can find Horusec's documentation on our [**website**](https://horusec.io/docs/).

## **Roadmap**
We have a project [**roadmap**](ROADMAP.md), you can contribute with us!

Horusec has other repositories, check them out:

- [**Horusec Platform**](https://github.com/ZupIT/horusec-platform)
- [**Horusec DevKit**](https://github.com/ZupIT/horusec-devkit)
- [**Horusec Engine**](https://github.com/ZupIT/horusec-engine)
- [**Horusec Operator**](https://github.com/ZupIT/horusec-operator)
- [**Horusec VsCode**](https://github.com/ZupIT/horusec-vscode-plugin)

## **Contributing**

Feel free to use, recommend improvements, or contribute to new implementations.

Check out our [**contributing guide**](CONTRIBUTING.md) to learn about our development process, how to suggest bugfixes and improvements. 

### **Developer Certificate of Origin - DCO**

 This is a security layer for the project and for the developers. It is mandatory.
 
Follow one of these two methods to add DCO to your commits:
 
**1. Command line**
 Follow the steps: 
 **Step 1:** Configure your local git environment adding the same name and e-mail configured at your GitHub account. It helps to sign commits manually during reviews and suggestions.

 ```
git config --global user.name “Name”
git config --global user.email “email@domain.com.br”
```
**Step 2:** Add the Signed-off-by line with the `'-s'` flag in the git commit command:

```
$ git commit -s -m "This is my commit message"
```
**2. GitHub website**

You can also manually sign your commits during GitHub reviews and suggestions, follow the steps below: 

**Step 1:** When the commit changes box opens, manually type or paste your signature in the comment box, see the example:

```
Signed-off-by: Name < e-mail address >
```

For this method, your name and e-mail must be the same registered on your GitHub account.

## **Code of Conduct**
Please follow the [**Code of Conduct**](https://github.com/ZupIT/horusec/blob/main/CODE_OF_CONDUCT.md) in all your interactions with our project.

## **License**
 [**Apache License 2.0**](LICENSE).

## **Community**

Feel free to reach out to us at:

- [**GitHub Issues**](https://github.com/ZupIT/horusec/issues)
- If you have any questions or ideas, let's chat in our [**Zup Open Source Forum**](https://forum.zup.com.br).


This project exists thanks to all the contributors. You rock! ❤️ 🚀

