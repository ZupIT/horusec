# Test book

# Table of Contents

 * [Horusec server](#horusec-server)
 * [Horusec messages](#horusec-messages)
 * [Horusec application admin](#horusec-application-admin)
 * [Horusec CLI](#horusec-cli)
 
 
## Horusec server
- [ ] Create account
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [X] Keycloak auth type
- [ ] Login
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [X] Keycloak auth type
- [ ] Logout
  - [X] Horusec auth type
- [ ] Authorize
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [X] Keycloak auth type
- [ ] Create, Read, Update and Delete company
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [X] Keycloak auth type
- [X] Create, Read, and Delete company token
- [X] Create, Read, Update, and Delete repositories
- [X] Create, Read, and Delete repository token
- [ ] Invite, Read, Update and Remove users in company
  - [X] Horusec auth type
  - [ ] Keycloak auth 
- [X] Create and Read analysis
  - [X] Repository Token
  - [X] Company Token + repository name
- [ ] Invite, Read, Update and Remove users in repository
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [ ] Keycloak auth type
- [X] Get Dashboard content
  - [X] Company view
  - [X] Repository view
- [X] Manager vulnerabilities found and change type into: False Positive, Risk accept, Corrected, Vulnerability

## Horusec messages
- [X] Create account
- [X] Validate account
- [X] Login
- [X] Logout
- [ ] Reset account password

## Horusec application admin
- [ ] Create account
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [ ] Keycloak auth type
- [ ] Login
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [ ] Keycloak auth type
- [ ] Logout
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [ ] Keycloak auth type
- [ ] Authorize
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [ ] Keycloak auth type
- [ ] Create, Read, Update and Delete company
  - [X] Horusec auth type
  - [ ] Ldap auth type
  - [ ] Keycloak auth type

## Horusec CLI
- [ ] Setup log level
- [ ] Output TEXT
- [ ] Output JSON
  - [ ] Changing filename
- [ ] Output SONARQUBE
  - [ ] Changing filename
- [ ] Ignore vulnerability by severity
- [ ] Ignore files or folder
- [ ] Timeout in analysis
- [ ] Timeout in request to send analysis  
- [ ] Return error `exit(1)` if found vulnerability
- [ ] Change directory to start analysis
- [ ] Send request with insecure tls
- [ ] Send request with certificate
- [ ] Run analysis in a current directory and filter paths
- [ ] Run analysis with git enable
- [ ] Run analysis with commit authors enable
- [ ] Run analysis with token of authorization
  - [ ] Repository token
  - [ ] Company token and repository name
- [ ] Run analysis and setup in flag vulnerability to:
  - [ ] False positive
  - [ ] Risk accept
- [ ] Run analysis using workdir
  - [ ] go
  - [ ] netCore
  - [ ] ruby
  - [ ] python
  - [ ] java
  - [ ] kotlin
  - [ ] javaScript
  - [ ] leaks
  - [ ] hlc
- [X] Scan languages GoLang
- [X] Scan languages C#
- [X] Scan languages Ruby
- [X] Scan languages Python
- [X] Scan languages Java
- [X] Scan languages Kotlin
- [X] Scan languages Javascript
- [X] Scan languages Leaks
- [X] Scan languages Terraform

### Generics repositories to test
- [ ] Kubernetes alone
- [ ] Apache Kafka
- [ ] gVisor
- [ ] Kubernetes and Kafka
