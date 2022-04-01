# **Security Policies**

Zup's Open Source projects adopt recommendations from the **OpenSSF Security Scorecards** and the **OpenSSF Best Practices Badge** program. Our projects must have a public policy for security vulnerabilities disclosure.

## **Supported versions**

|Version                   |Supported |
|---                       |---       |
|Latest branch version     |Yes       |
|Other versions            |No        |

### **Private Disclosure Process of Vulnerabilities**

Zup's Open Source Engineering team and its product communities care about reported security vulnerabilities.

Our community request that every suspected vulnerability are disclosed privately and responsibly.
If you find a vulnerability or even a possible one, follow the instructions:

**1.** Send us an e-mail to **secure.opensource@zup.com.br**. You need to add the information below:

- Type of vulnerability (for example Buffer Overflow, SQL Injection, Cross-Site Scripting, etc.).
- Full paths of the source files related to the vulnerability manifestation.
- The location of the affected source code (tag/branch/commit or direct URL).
- Step-by-step instructions to reproduce the problem and you can also add any special configuration required to it.
- Proof-of-concept or exploit code (if possible).
- The impact of the problem, including how an attacker might exploit the vulnerability.

**2.** The **Horusec** team will acknowledge your e-mail and they will send you a more detailed response indicating the next steps to handle the vulnerability you have reported.

**3.** The **Horusec** team will keep you informed about the progress of the fix and its public disclosure. They may ask you for additional information.

### **Public Disclosure Process of Vulnerabilities**

If you become aware of a publicly disclosed vulnerability, please IMMEDIATELY send an e-mail to secure.opensource@zup.com.br, informing the **Horusec** team about it so they can address it via analysis, fix, new versioning, and release.

Whenever is possible, the **Horusec** team may request the person who made the vulnerability's public disclosure to address it through a private process, for example, if details about exploiting the flaw are not available yet.

### **Disclosure Policy**

When the **Horusec** team receives a vulnerability report, a team member is assigned as a primary handler. This person will contact the product's Tech Lead to coordinate the bug fix and new fixed version release process, see the steps of this process below:

**Step 1.** Confirm the issue and determine if the supported version is affected;

**Step 2.** Audit code to find similar issues;

**Step 3.** Prepare fixes for the supported version. These fixes will be released as soon as possible.

### **Community**

If you have any suggestions on how we can improve this process, please submit a pull request and contribute to the project too!
