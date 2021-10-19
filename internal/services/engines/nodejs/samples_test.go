// Copyright 2021 ZUP IT SERVICOS EM TECNOLOGIA E INOVACAO SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nodejs

const (
	SampleSafeJavaScriptUseEval = `
function f() {
	eval("echo foo");
}
	`

	SampleVulnerableJavaScriptDisableTlsRejectUnauthorized = `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
	`
	SampleVulnerableJavaScriptUseEval = `
function f(req) {
	eval("bash -c" + req.body);
}
	`
	SampleVulnerableJavaScriptLogSensitiveInformation = `
console.log("user email: ", email) 
console.debug("user password: ", pwd) 
	`
)
