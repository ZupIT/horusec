# **Contributing Guide**

This is Horusec contributing guide. Please read the following sections to learn how to ask questions and how to work on something.

## **Table of contents**
### 1. [**Before you contribute**](#before-you-contribute)
> #### i.  [**Code of Conduct**](#code-of-conduct)
> #### ii. [**Legal**](#legal)
### 2. [**Prerequisites**](#prerequisites)
> #### i.   [**Developer Certificate of Origin**](#developer-certificate-of-origin)
> #### ii.  [**Code Review**](#code-review)
> #### iii. [**Pull Requests**](#pull-requests)    
### 3. [**How to contribute?**](#how-to-contribute?)
 > #### i. [**Prepare your development environment**](#prepare-your-development-environment)
> #### ii.  [**First contribution**](#first-contribution)
> #### iii. [**Add new feature, bugfixing or improvement**](#add-new-feature-bugfixing-or-improvement)
> #### iv.  [**Pull Request's approval**](#pull-request-approval)
> #### v.   [**After your pull request's approval**](#after-your-pull-request-approval)
### 4. [**Community**](#community)

## **Before you contribute**

### **Code of Conduct**
Please follow the [**Code of Conduct**](https://github.com/ZupIT/horusec/blob/main/CODE_OF_CONDUCT.md) in all your interactions with our project.

### **Legal**
- Horusec is licensed over [**ASF - Apache License**](https://github.com/ZupIT/horusec/blob/main/LICENSE), version 2, so new files must have the ASF version 2 header. For more information, please check out [**Apache license**](https://www.apache.org/licenses/LICENSE-2.0).

- All contributions are subject to the [**Developer Certificate of Origin (DCO)**](https://developercertificate.org). 
When you commit, use the ```**-s** ``` option to include the Signed-off-by line at the end of the commit log message.

## **Prerequisites**
Check out the requisites before contributing to Horusec:

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

For this method, your name and e-mail must be the same registered to your GitHub account.

### **Code Review**
- All your submissions needs a review.

### **Pull Requests**
When you open a PR, follow the requisites below:
- You need to add a title describing the issue. 
- Answer the questions about what you did, how to verify it and a description for the changelog, see an example:

<p align="center" margin="20 0"><img src="assets/horusec-pr.PNG" alt="architecture" width="100%" style="max-width:100%;"/></p>


## **How to contribute?** 
See the guidelines to submit your changes: 

### **Prepare your development environment**
To start contributing with Horusec you first need to install [Go](https://golang.org/dl/). The minimal version required to build is 1.17.
[GNU Make](https://www.gnu.org/software/make/) is also required to development.

After installing Go you can build using `make build-dev`.


#### **Testing**
Horusec has a suite of unit and end-to-end tests you can run them using the following commands. 

```
make test

make test-e2e
```

Make sure all the tests pass before you commit and push :)

#### **Coverage**
You can get the test coverage using the following command.

```bash
make coverage

go tool cover -html=coverage.out # Open coverage status in your browser
``` 

#### **Repositories**
Horusec has other repositories and you can check the README for each one of them: 

- [**Charts**](https://github.com/ZupIT/charlescd/tree/main/circle-matcher)
- [**Devkit**](https://github.com/ZupIT/horusec-devkit)
- [**Engine**](https://github.com/ZupIT/horusec-engine)
- [**Jenkins**](https://github.com/ZupIT/horusec-jenkins-sharedlib)
- [**Operator**](https://github.com/ZupIT/horusec-operator)
- [**Platform**](https://github.com/ZupIT/horusec-platform)
- [**VSCode plugin**](https://github.com/ZupIT/horusec-vscode-plugin)
- [**Kotlin**](https://github.com/ZupIT/horusec-tree-sitter-kotlin)
- [**Vulnerabilities**](https://github.com/ZupIT/horusec-examples-vulnerabilities)

### **First contribution**
Contributing to a new feature is only allowed in the [**main repository**](https://github.com/ZupIT/horusec).

Before contributing to this repository, please discuss the changes you wish to make via e-mail or [**forum**](https://forum.zup.com.br/c/en/horusec/14). 

### **Add new feature, bugfixing or improvement**
If you want to add an improvement, a new feature or bugfix, follow the steps to contribute: 

**Step 1:** Make sure your branch is based on main;
**Step 2:** When opening an issue, choose a template to answer the questions regarding the what you want to contribute: 
- [**Bug Report**](https://github.com/ZupIT/horusec/blob/main/.github/ISSUE_TEMPLATE/bug_report.md)
- [**Feature request**](https://github.com/ZupIT/horusec/blob/main/.github/ISSUE_TEMPLATE/feature_request.md)
- [**Improvement**](https://github.com/ZupIT/horusec/blob/main/.github/ISSUE_TEMPLATE/improvement.md)
- [**Support request**](https://github.com/ZupIT/horusec/blob/main/.github/ISSUE_TEMPLATE/support_request.md)

**Step 3:** Make your changes and open a GitHub pull request;

**Step 4:** Make sure to write a title describing what you have done;

**Step 5:** Fill in the template in the PR, here you need to write what you did and how the team can verify it; 

**Step 6:** You must commit to comply with the DCO rules. It will need to be [**signed-off**](https://git-scm.com/docs/git-commit#Documentation/git-commit.txt--s) and [**verified**](https://docs.github.com/en/github/authenticating-to-github/managing-commit-signature-verification/about-commit-signature-verification). Example: ` git commit -s --amend`.


### **Pull Request's approval**
Your pull request is approved when:
- 2 code owners approve it.
- Pass all GitHub actions checking process (lint, test, coverage, license, build, e2e, security, dco).

### **After your pull request's approval**
- If it is a bugfix, the team will perform the changes and there will be a new release.
- If it is a feature, it will be in the next release. 

## **Community**

- Do you have any question about Horusec in our [**mailing list**](horusec@zup.com.br) 
- Let's chat in our [**forum**](https://forum.zup.com.br/c/en/horusec/14).

Thank you for your contribution, you rock! 🚀

**Horusec team** 
