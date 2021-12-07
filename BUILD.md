# **BUILD**

## **Table of contents** 
### 1. [**About**](#about)
### 2. [**Environment**](#environment)
### 3. [**Development**](#development)
>#### 3.1. [**Install and Run**](#install-and-run)
>#### 3.2. [**Style Guide**](#style-guide)
>#### 3.3. [**Tests**](#security)
>##### 3.3.1 [**E2E**](#e2e)
>##### 3.3.2 [**Unitary Tests**](#unitary-tests)
>#### 3.4 [**Security**](#security)       
### 4. [**Production**](#production)


## **About**
The **BUILD.md** is a file to check the environment and build specifications of **horusec-cli** project.


## **Environment**

- **Golang**: ^1.17.X

## **Development**

Use a command-line interface (CLI) of your choice to run the following commands to download and install the dependencies.

### **Install and Run**

From the root of the project, run the command below to download the dependencies:

```go
go mod download
```

The command below allows the execution of the program, run it in the root folder:

```bash
make build-dev && ./horusec
```

### **Style Guide**

There is a pattern for the source code and the [**golangci-lint**](https://golangci-lint.run) tool is used as an aggregator to the Golang's linter.
You can check lint through the `make` command, see it below:

```bash
make lint
```

The project also has a dependency import stardard, and the command below organizes your code in the stardard definied:

```bash
make format
```

All project files must have the [**license header**](./copyright.txt). To check if all files are in agreement, run the command:

```bash
make license
```

If you need to add the license in any file, the command below inserts it in all files that do not have it:

```bash
make license-fix
```

### **Tests**

The source code has two test segments, E2E and unitary test.

#### **E2E**

The e2e tests were writen with the packages:

- [**Ginkgo**](https://onsi.github.io/ginkgo/)
- [**Gomega**](https://onsi.github.io/gomega/)

You can run the tests by the command below:

```bash
make test-e2e
```

#### **Unitary Tests**

The unit tests were written with the [**Golang standard**](https://pkg.go.dev/testing) package and some mock and assert snippets, we used the [**testify**](https://github.com/stretchr/testify). You can run the tests using the command below:

```bash
make test
```

To check test coverage, run the command below:

```bash
make coverage
```

### **Security**

[**Horusec**](https://horusec.io/site/) uses the latest version to keep our source code safe. You can verify using the command below:

```bash
make security
```

## **Production**

Run the commands below in your project's root according to your Operating System to create Horusec's binary:

- **Windows**

  ```bash
  make build-install-cli-windows
  ```

- **Linux**

  ```bash
  make build-install-cli-linux
  ```

- **MacOs**

  ```bash
  make build-install-cli-darwin
  ```
