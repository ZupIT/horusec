# **Contributing Guide**

This is Horusec contributing guide. Please read the following sections to learn how to ask questions and how to work on something.

## **Table of contents**
1. [**Getting Started**](#Getting-started)
   1. [**Before you contribute**](#Before-you-contribute)
   2. [**Code of Conduct**](#Code-of-Conduct)
   3. [**Legal**](#Legal)
2. [**Prerequisites**](#Prerequisites)
   1. [**Developer Certificate of Origin**](#Developer-Certificate-of-Origin)
   2. [**Code Review**](#Code-Review)
   3. [**Pull Requests**](#Pull-Requests)    
3. [**How to contribute?**](#How-to-contribute?)
      1. [**Prepare your development environment**](#Using-Docker)
      2. [**First contribution**](#First-contribution)
      4. [**Add new feature, bugfixing or improvement**](#Add-new-feature-bugfixing-or-improvement)
      5. [**Pull Request's approval**](#Pull-Request's-approval)
      6. [**After your pull request's approval**](#After-your-pull-request's-approval)
4. [**Community**](#Community)

## **Getting started**

### **Before you contribute**

### **Code of Conduct**
Please follow the [**Code of Conduct**](https://github.com/ZupIT/horusec/blob/main/CODE_OF_CONDUCT.md) in all your interactions with our project.

### **Legal**
- Horusec is licensed over [**ASL - Apache License**](https://github.com/ZupIT/charlescd/blob/main/LICENSE), version 2, so new files must have the ASL version 2 header. For more information, please check out [**Apache license**](https://www.apache.org/licenses/LICENSE-2.0).

- All contributions are subject to the [**Developer Certificate of Origin (DCO)**](https://developercertificate.org). 
When you commit, use the ```**-s** ``` option to include the Signed-off-by line at the end of the commit log message.

## **Prerequisites**
Check out the requisites before contributing to Horusec:

### **Developer Certificate of Origin - DCO**

 This is a security layer for the project and for the developers. It is mandatory.
 
 There are two ways to use DCO, see them below: 
 
**1. Command line**
 Follow the steps: 
 **Step 1:** Check out your local git:

 ```
git config --global user.name “Name”
git config --global user.email “email@domain.com.br”
```
**Step 2:** When you commit, add the sigoff via `-s` flag:

```
$ git commit -s -m "This is my commit message"
```
**2. GitHub website**

**Step 1:** When the commit changes box opens, add 
```
$ git commit -m “My signed commit” Signed-off-by: username <email address>
```
Note: For this option, your e-mail must be the same in registered in GitHub. 

### **Code Review**
- All your submissions needs a review.

### **Pull Requests**
When opening a PR: 
- You need to add a title describing the issue. 
- Fill in the template, describe why you are opening the PR.

## **How to contribute?** 
See the guidelines to submit your changes: 

### **Prepare your development environment**
Horusec has other repositories and you can check the README for each one of them: 

- [**Admin**](https://github.com/ZupIT/horusec-admin)
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

Before contributing to this repository, please discuss the changes you wish to make via email or [**forum**](https://forum.zup.com.br/c/en/horusec/14). 

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