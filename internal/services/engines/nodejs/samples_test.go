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
	SampleVulnerableHSJAVASCRIPT1 = `
console.log("user email: ", email)
console.debug("user password: ", pwd)
`

	SampleVulnerableHSJAVASCRIPT2 = `
function f(req) {
	eval("bash -c" + req.body);
}
`

	SampleVulnerableHSJAVASCRIPT3 = `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
`

	SampleVulnerableHSJAVASCRIPT4 = `
const hash = crypto.createHash('md5')
`

	SampleVulnerableHSJAVASCRIPT5 = `
const hash = crypto.createHash('sha1')
`

	SampleVulnerableHSJAVASCRIPT6 = `
function f() {
	return Math.random();
}
`

	SampleVulnerableHSJAVASCRIPT7 = `
function f(req) {
	return fs.readFileSync(req.body, 'utf8')
}
`

	SampleVulnerableHSJAVASCRIPT8 = `
function f(req) {
	return fs.createReadStream(req.body)
}
`
	SampleVulnerableHSJAVASCRIPT9 = `
function f(req) {
	Model.find({ where: { foo: req.body}});
}
	`

	SampleVulnerableHSJAVASCRIPT10 = `
var libxml = require("libxmljs2");

var xmlDoc = libxml.parseXmlString(xml, {});
	`

	SampleVulnerableHSJAVASCRIPT11 = `
function f() {
	var popup = window.open();
	popup.postMessage("message", "https://foo.bar", "*");
}

function f2() {
	window.addEventListener("message", (event) => {});
}
	`

	SampleVulnerableHSJAVASCRIPT12 = `
function f() {
	const options = {
		secureProtocol: 'TLSv1_method'
	}
}

function f2() {
	const options = {
		secureProtocol: 'TLSv1.1'
	}
}
	`

	SampleVulnerableHSJAVASCRIPT13 = `
const db = window.openDatabase();
	`

	SampleVulnerableHSJAVASCRIPT14 = `
function f() {
	localStorage.setItem("foo", "bar");
}

function f2() {
	sessionStorage.setItem("foo", "bar");
}
	`

	SampleVulnerableHSJAVASCRIPT15 = `
	debugger;
	`

	SampleVulnerableHSJAVASCRIPT16 = `
function f() {
	alert("testing");
}

function f2() {
	confirm("testing");
}

function f3() {
	prompt("testing");
}
	`

	SampleVulnerableHSJAVASCRIPT17 = `
app.use('/', express.static('public', {
  dotfiles : 'allow'
}));
	`

	SampleVulnerableHSJAVASCRIPT18 = `
function success(pos) {
	console.log(pos)
}

function error(err) {
  console.warn(err);
}

navigator.geolocation.getCurrentPosition(success, error, {});
	`
)

const (
	SampleSafeHSJAVASCRIPT2 = `
function f() {
	eval("echo foo");
}
`

	SampleSafeHSJAVASCRIPT9 = `
function f(foo) {
	Model.find({ where: { foo: foo}});
}
`

	SampleSafeHSJAVASCRIPT10 = `
var libxml = require("libxmljs2");

var xmlDoc = libxml.parseXmlString(xml);
	`

	SampleSafeHSJAVASCRIPT11 = `
function f() {
	var popup = window.open();
	popup.postMessage("message", "https://foo.bar");
}

function f2() {
	window.addEventListener("message", (event) => {
		if (event.origin !== "http://example.org:8080") {
			return;
		}
	});
}
	`

	SampleSafeHSJAVASCRIPT12 = `

function f() {
	const options = {
		secureProtocol: 'SSLv23_method'
	}
}
	`

	SampleSafeHSJAVASCRIPT17 = `
app.use('/', express.static('public', { }));

	`
)
