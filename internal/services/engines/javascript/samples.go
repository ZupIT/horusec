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

package javascript

const (
	SampleVulnerableHSJAVASCRIPT1 = `
console.log("user email: ", email)
console.debug("user password: ", pwd)
`
	SampleSafeHSJAVASCRIPT1 = ``

	SampleVulnerableHSJAVASCRIPT2 = `
function f(req) {
	eval(foo);
}
`
	SampleSafeHSJAVASCRIPT2 = `
function f() {
	window.eval("any string")
}
`

	SampleVulnerableHSJAVASCRIPT3 = `
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
`
	SampleSafeHSJAVASCRIPT3 = ``

	SampleVulnerableHSJAVASCRIPT4 = `
const hash = crypto.createHash('md5')
`
	SampleSafeHSJAVASCRIPT4 = ``

	SampleVulnerableHSJAVASCRIPT5 = `
const hash = crypto.createHash('sha1')
`
	SampleSafeHSJAVASCRIPT5 = ``

	SampleVulnerableHSJAVASCRIPT6 = `
function f() {
	return Math.random();
}
`
	SampleSafeHSJAVASCRIPT6 = ``

	SampleVulnerableHSJAVASCRIPT7 = `
function f(req) {
	return fs.readFileSync(req.body, 'utf8')
}
`
	SampleSafeHSJAVASCRIPT7 = ``

	SampleVulnerableHSJAVASCRIPT8 = `
function f(req) {
	return fs.createReadStream(req.body)
}
`
	SampleSafeHSJAVASCRIPT8 = ``

	SampleVulnerableHSJAVASCRIPT9 = `
function f(req) {
	Model.find({ where: { foo: req.body}});
}
`
	SampleSafeHSJAVASCRIPT9 = `
function f(foo) {
	Model.find({ where: { foo: foo}});
}
`

	SampleVulnerableHSJAVASCRIPT10 = `
var libxml = require("libxmljs2");

var xmlDoc = libxml.parseXmlString(xml, {});
`
	SampleSafeHSJAVASCRIPT10 = `
var libxml = require("libxmljs2");

var xmlDoc = libxml.parseXmlString(xml);
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
	SampleSafeHSJAVASCRIPT12 = `

function f() {
	const options = {
		secureProtocol: 'SSLv23_method'
	}
}
`

	SampleVulnerableHSJAVASCRIPT13 = `
const db = window.openDatabase();
	`
	SampleSafeHSJAVASCRIPT13 = ``

	SampleVulnerableHSJAVASCRIPT14 = `
function f() {
	localStorage.setItem("foo", "bar");
}

function f2() {
	sessionStorage.setItem("foo", "bar");
}
`
	SampleSafeHSJAVASCRIPT14 = ``

	SampleVulnerableHSJAVASCRIPT15 = `
debugger;
`
	SampleSafeHSJAVASCRIPT15 = ``

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
	SampleSafeHSJAVASCRIPT16 = ``

	SampleVulnerableHSJAVASCRIPT17 = `
app.use('/', express.static('public', {
  dotfiles : 'allow'
}));
	`
	SampleSafeHSJAVASCRIPT17 = `
app.use('/', express.static('public', { }));

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
	SampleSafeHSJAVASCRIPT18 = ``

	SampleVulnerableHSJAVASCRIPT19 = `
var corsOptions = {
  origin: '*',
}

app.get('/products/:id', cors(), function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.json({msg: 'This is CORS-enabled for only domain.'});
})
`
	SampleSafeHSJAVASCRIPT19 = `
var corsOptions = {
  origin: 'http://horusec.io',
}

app.get('/products/:id', cors(corsOptions), function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "http://horusec.io");
  res.json({msg: 'This is CORS-enabled for only domain.'});
})
`

	SampleVulnerableHSJAVASCRIPT20 = ``
	SampleSafeHSJAVASCRIPT20       = ``

	SampleVulnerableHSJAVASCRIPT21 = ``
	SampleSafeHSJAVASCRIPT21       = ``

	SampleVulnerableHSJAVASCRIPT22 = ``
	SampleSafeHSJAVASCRIPT22       = ``

	SampleVulnerableHSJAVASCRIPT23 = ``
	SampleSafeHSJAVASCRIPT23       = ``

	SampleVulnerableHSJAVASCRIPT24 = ``
	SampleSafeHSJAVASCRIPT24       = ``

	SampleVulnerableHSJAVASCRIPT25 = ``
	SampleSafeHSJAVASCRIPT25       = ``

	SampleVulnerableHSJAVASCRIPT26 = ``
	SampleSafeHSJAVASCRIPT26       = ``

	SampleVulnerableHSJAVASCRIPT27 = ``
	SampleSafeHSJAVASCRIPT27       = ``

	SampleVulnerableHSJAVASCRIPT28 = ``
	SampleSafeHSJAVASCRIPT28       = ``

	SampleVulnerableHSJAVASCRIPT29 = ``
	SampleSafeHSJAVASCRIPT29       = ``

	SampleVulnerableHSJAVASCRIPT30 = ``
	SampleSafeHSJAVASCRIPT30       = ``

	SampleVulnerableHSJAVASCRIPT31 = ``
	SampleSafeHSJAVASCRIPT31       = ``

	SampleVulnerableHSJAVASCRIPT32 = ``
	SampleSafeHSJAVASCRIPT32       = ``

	SampleVulnerableHSJAVASCRIPT33 = ``
	SampleSafeHSJAVASCRIPT33       = ``

	SampleVulnerableHSJAVASCRIPT34 = ``
	SampleSafeHSJAVASCRIPT34       = ``

	SampleVulnerableHSJAVASCRIPT35 = ``
	SampleSafeHSJAVASCRIPT35       = ``

	SampleVulnerableHSJAVASCRIPT36 = ``
	SampleSafeHSJAVASCRIPT36       = ``

	SampleVulnerableHSJAVASCRIPT37 = ``
	SampleSafeHSJAVASCRIPT37       = ``

	SampleVulnerableHSJAVASCRIPT38 = ``
	SampleSafeHSJAVASCRIPT38       = ``

	SampleVulnerableHSJAVASCRIPT39 = ``
	SampleSafeHSJAVASCRIPT39       = ``

	SampleVulnerableHSJAVASCRIPT40 = ``
	SampleSafeHSJAVASCRIPT40       = ``

	SampleVulnerableHSJAVASCRIPT41 = ``
	SampleSafeHSJAVASCRIPT41       = ``

	SampleVulnerableHSJAVASCRIPT42 = ``
	SampleSafeHSJAVASCRIPT42       = ``

	SampleVulnerableHSJAVASCRIPT43 = ``
	SampleSafeHSJAVASCRIPT43       = ``

	SampleVulnerableHSJAVASCRIPT44 = ``
	SampleSafeHSJAVASCRIPT44       = ``

	SampleVulnerableHSJAVASCRIPT45 = ``
	SampleSafeHSJAVASCRIPT45       = ``

	SampleVulnerableHSJAVASCRIPT46 = ``
	SampleSafeHSJAVASCRIPT46       = ``

	SampleVulnerableHSJAVASCRIPT47 = ``
	SampleSafeHSJAVASCRIPT47       = ``

	SampleVulnerableHSJAVASCRIPT48 = ``
	SampleSafeHSJAVASCRIPT48       = ``

	SampleVulnerableHSJAVASCRIPT49 = ``
	SampleSafeHSJAVASCRIPT49       = ``

	SampleVulnerableHSJAVASCRIPT50 = ``
	SampleSafeHSJAVASCRIPT50       = ``

	SampleVulnerableHSJAVASCRIPT51 = ``
	SampleSafeHSJAVASCRIPT51       = ``

	SampleVulnerableHSJAVASCRIPT52 = ``
	SampleSafeHSJAVASCRIPT52       = ``

	SampleVulnerableHSJAVASCRIPT53 = ``
	SampleSafeHSJAVASCRIPT53       = ``
)
