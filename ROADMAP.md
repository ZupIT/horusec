# Horusec Public Roadmap

Our planning focused on the Open Source product and considered a twelve-month vision, presenting the next steps that we have thought about and contributed to the evolution of Horusec. We value quality and transparency during our process, and this will be the primary place to follow Horusec roadmap latest updates. We will keep you informed and adjust our roadmap according to the team's capacity and priorities to maintain quality. On this page, you will follow and be part of Horusec's growth in these areas: **Engineering and product management**. Besides, we have a space for new ideas, **so find out with us**.

## Open source software engineering

### Functionalities we currently have

<details><summary><a href="https://github.com/ZupIT/horusec" alt="license">CLI</a></summary><br>

- Download binaries for Arm and AMD processor architecture
- Locally vulnerability analysis via command-line interface
- Vulnerability Analysis on CI / CD Treadmill: GitHub Actions, AWS Code Build, Circle Ci, Jenkins, Azure DevOps Pipeline, Gitlab Ci / CD
- Vulnerability analysis via Docker image using volumes.
- Analysis of Dependency: NPM, Yarn, Pypim, Ruby, C #, Go.Mod
- User Custom Rules
- análiseSast (staticApplicationSecurityTesting)ParaLinguagens:C#,Java,Kotlin,Python,Ruby,Golang,Terraform,Javascript,Typescript,Kubernetes,Php,C,C++,Html,Json,Dart,Elixir,Shell,Nginx,Swift
- LEAKS ANALYSIS: Certificates, AWS Keys, Google Cloud Keys, Private Keys, among others.
- Leaks analysis in historic git
- Motor Sast (Static Application Security Testing) for Vulnerabilities Detection.
- CLI without Docker's dependence.
- Export of analysis in formats: JSON, Sonarqube, text
- Local vulnerability treatment between: false positive, risk accepted
- Automatic generation of configuration file
- HTTPS Support for Integration with Horusec-API
- Dynamic Headers Support for Horusec-API Integration
- Show commit authors
- Possibility to ignore files and folders dynamically
- Possibility of ignoring vulnerability by the severity level
- Timeout and dynamic verification time to finalize analysis
- Possibility of analysis in dynamic directories
- Option to break pipeline dynamically
- Code Recommendations Not vulnerable and vulnerable

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-platform" alt="license">Web Platform</a></summary><br>

- Facilitated installation via horusec-operator
- Installation via Charts Kubbernetes
- Installation via docker image
- Vulnerabilities Management (Basic): Identify, change the severity, change the type of vulnerability found between vulnerability, false positive, accepted and corrected risk.
- MultiTenancy
- Vulnerability Dashboard in Workspace or Repository Vision
- Possibility to download Dashboard data for files in PDF, XLS, XML, CSV, PNG, JSON
- Customizable authentication type (LDAP, KEYCLOAK, HORUSEC)
- Simplified navigation by the type of vision (Workspace or repository)
- Vulnerabilities Chart By: Repository, Language, Person Development, Criticity
- Time line of vulnerabilities occurrences
- Integration with CLI using workspace token or repository authorization with the possibility of dynamic expiration.
- Access Invitation to Repositories, Workspaces, Vulnerability Management between (Administrator, Supervisor, User)
- E-mail Shooting and Receiving Invitations for Workspaces
- Webhook Shooting Integration to send analysis to third-party APIs.
- Web Accessibility (A11Y) in Horusec-Manager
- A18N Between (Portuguese, English, Spanish)

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-vscode-plugin" alt="license">Plugin to Visual Studio Code</a></summary><br>

- All CLI settings options within VSCODE
- Dynamic loading when analysis is being executed
- Vulnerability tab with icons and quick link to the vulnerability site

</details>

### Functionality that is feasible and we want to have


<details><summary><a href="https://github.com/ZupIT/horusec" alt="license">CLI</a></summary><br>

- Semantic Analysis JavaScript
- Semantic analysis Java
- Semantic analysis Kotlin
- Semantic Analysis C#
- Semantic Analysis Dart
- Semantic Analysis Typscript
- Semantic Analysis Swift
- Semantic analysis Nginx
- Semantic analysis Kubernetes
- Semantic analysis Leaks
- Decrease the amount of false positives.
- Tab Completion in CLI
- Improve observability in the project.
- Improve Horusec Logs for example: "Remove Left Time", "Remove Unnecessary Warning", "Swap Timeout Log for Progress Bar", "Option for --Quiet no logs"

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-platform" alt="license">Web Platform</a></summary><br>

- Integration to any code analysis tool (Gitchuardian, Snik, etc ...)
- Dashboard to accompany companies and cases of vulnerability
- Screen for the user Enter custom rules through Manager.
- Has options for graphs and queries, for example, failure indicator that entered or decreased in the last version
- Add historical and vulnerability life cycle tracking.
- Exporting vulnerability reports
- Decrease the amount of false positives.
- Improve observability in the project.
- Migrate data from other platforms (Fortify, Sonarqube, Defectdojo) to automatically include in Horusec-Manager
- Decrease the amount of false positives.
- Repositories, Favorites and other features for facilitating experience on the platform

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-vscode-plugin" alt="license">Plugin to Visual Studio Code</a></summary><br>

- Use via Docker or Binary
- Project Code Architecture Mapping
- Perform end to end

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-intellij-plugin" alt="license">Plugin to IntelliJ</a></summary><br>

- Creation and availability of the plugin for Intellij IDE

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-visual-studio-plugin" alt="license">Plugin to Visual Studio</a></summary><br>

- Creating and availability of the plugin for Visual Studio IDE

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-android-studio-plugin" alt="license">Plugin to Android Studio</a></summary><br>

- Creation and availability of the plugin for IDE Android Studio

</details>

### Functionality that are our dream in having, but we do not know how to do

<details><summary><a href="https://github.com/ZupIT/horusec" alt="license">CLI</a></summary><br>

- DAST (Dynamic Application Security Test)
- A simple model to include new market tools without needing to move in source code
- Automatic corrections based on recommendations
- READ (Read Eval Print Loop) to create rules and already test results
- Introduce Horusec in Stores, such as Ubuntu Store, Apt-Get, AUR, Windows ...
- Semantic analysis that enables users to write their own rules
- Create a UI To use Horusec in Windows (something like Next, Next, Install, runs the folder and view the analysis through a Windows installation interface, Ubuntu, Mac)

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-platform" alt="license">Web Platform</a></summary><br>

- Dashboard following previous behaviors to predict new types of incidents and anticipate our action with Horusec using IA
- Grouper of the most common security problems in my application
- Vulnerability Management with Automated Security Complete Reports

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-vscode-plugin" alt="license">Plugin to Visual Studio Code</a></summary><br>

- Include design of the project architecture as well as fortify does to demonstrate why that is a vulnerability.

</details>

<details><summary><a href="https://github.com/ZupIT/horusec-playground" alt="license">Horusec Playground</a></summary><br>

- Include a format that the user can test the horusec on a site without having to download

</details>


## Discover with us

We dedicate this part to get your vision and innovative ideas to create better Horusec features and to improve your developer experience.  Let us know if these new ideas make sense and be part of this discovery! 
