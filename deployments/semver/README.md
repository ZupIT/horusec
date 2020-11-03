# Semantic Versioning Tool

An easy to use CLI tool to manage your projects current version and its upgrades according to the Semantic Versioning specification.


## Getting Started

### Install
**Run in root directory horusec**
```sh
make install-semver
```

### check install
Check if the semver was installed running the command:
```sh
semver 
```


### Init semver
To start managing your project versions enter into the project folder, then run:
```sh
semver init
```

This command will start the versioning based on release version v1.0.0. If you want to start with another version number you car run instead:
```sh
semver init  \
    --release [base release version] \
    [ --alpha [curent alpha number] ] \
    [ --beta [current beta number] ] \
    [ --rc [current release candiate number] ] \
    [--force] # to override an already initialized semver in the current directory.
```


## Usage

### Get current version
#### Alpha
Returns the current alpha version (if none will return and "-alpha.0" version).
```sh
$ semver get alpha
v1.0.0-alpha.6
```

#### Beta
Returns the current beta version (if none will return and "-beta.0" version).
```sh
$ semver get beta
v1.0.0-beta.3
```

#### Release Candidate
Returns the current release candidate version (if none will return and "-rc.0" version).
```sh
$ semver get rc
v1.0.0-rc.1
```

#### Release
Returns the current release version.
```sh
$ semver get release
v1.0.0
```

### Upgrade version
#### Alpha
Increment the current alpha version by 1. If none starts with 1.
```sh
$ semver up alpha
v1.0.0-alpha.7
```

#### Beta
Increment the current beta version by 1. If none starts with 1.
```sh
$ semver up beta
v1.0.0-beta.4
```

#### Release Candidate
Increment the current release candidate version by 1. If none starts with 1.
```sh
$ semver up rc
v1.0.0-rc.2
```

#### Release
Upgrade an alpha, beta or rc to its final release version. Also increments the patch number by 1 to a release version:
```sh
$ semver up release
v1.0.0

$ semver up release
v1.0.1
```

#### Minor
Increments release minor version number by 1 (useful when you start working on next release version) and clear alpha, beta, rc and patch number.
```sh
$ semver up minor
v1.1.0
```

Before you upgrade the minor version the next versions will be generated based on this new minor version.
```sh
$ semver up alpha
v1.1.0-alpha.1

$ semver up beta
v1.1.0-beta.1

$ semver up rc
v1.1.0-rc.1
```

#### Major
Upgrades the current version to the next major version (when you starts working on a new version with branking changes) and clear alpha, beta, rc, patch and minor number.
```sh
$ semver up major
v2.0.0
```

Before them, your next versions will be generated based on this new version.
```sh
$ semver up alpha
v2.0.0-alpha.1

$ semver up beta
v2.0.0-beta.1

$ semver up rc
v2.0.0-rc.1
```
