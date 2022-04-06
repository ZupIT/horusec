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
	SampleSafeHSJAVASCRIPT3 = `process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";`

	SampleVulnerableHSJAVASCRIPT4 = `
const hash = crypto.createHash('md5')
`
	SampleSafeHSJAVASCRIPT4 = `const hash = crypto.createHash('sha256')`

	SampleVulnerableHSJAVASCRIPT5 = `
const hash = crypto.createHash('sha1')
`
	SampleSafeHSJAVASCRIPT5 = `const hash = crypto.createHash('sha512')`

	SampleVulnerableHSJAVASCRIPT6 = `
function f() {
	return Math.random();
}
`
	SampleSafeHSJAVASCRIPT6 = `
function f() {
	const randomBuffer = new Uint32Array(1);
	(window.crypto || window.msCrypto).getRandomValues(randomBuffer);
	const uint = randomBuffer[0];
}
`
	SampleVulnerableHSJAVASCRIPT7 = `
function f(req) {
	return fs.readFileSync(req.body, 'utf8')
}
`
	SampleSafeHSJAVASCRIPT7 = `
function f(req) {
	const sanitize = require("sanitize-filename");
	const userInput = sanitize(req.body)
	return fs.readFileSync(userInput, 'utf8')
}
`
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

	SampleVulnerableHSJAVASCRIPT20 = `
function f() {
	var input = process.stdin.read();
	console.log(input);
}
`
	SampleSafeHSJAVASCRIPT20 = ``

	SampleVulnerableHSJAVASCRIPT21 = `
function f() {
	console.exec(process.argv[0])
}
`
	SampleSafeHSJAVASCRIPT21 = `
function f() {
	var userArgs = mySanitizer(process.argv[0])
	console.exec(userArgs);
}
`
	SampleVulnerableHSJAVASCRIPT22 = `
function f() {
	const { path } = req.body;
	redirect(path);
}
`
	SampleSafeHSJAVASCRIPT22 = `
function f() {
	const { path } = req.body;
	const sanitizedPath = mySanitizer(path)
	redirect('https://myOrigin/' + sanitizedPath);
}
`
	SampleVulnerableHSJAVASCRIPT23 = `
function f() {
	return response.render(req.body.data);
}

function f() {
	return response.send(req.body.content);
}
`
	SampleSafeHSJAVASCRIPT23 = `
function f() {
	const { content } = req.body;
	const sanitizedContent= mySanitizer(content)
	return response.send(sanitizedContent)
}
`
	SampleVulnerableHSJAVASCRIPT24 = `
function f() {
	return document.write(req.body.data);
}

function f() {
	return body.write(req.body.content);
}

function f() {
	const element = document.getElementById('title')
	return element.write(req.body.content);
}
`
	SampleSafeHSJAVASCRIPT24 = `
function f() {
	const { content } = req.body;
	const element = document.getElementById('title')
	const sanitizedContent= mySanitizer(content)
	return element.write(sanitizedContent);
}
`
	SampleVulnerableHSJAVASCRIPT25 = `
function f() {
	try {
		const allUsers = db.users.getAll()
		return res.send(allUsers)
	} catch (err) {
		return res.send(err.stack);
	}
}
`
	SampleSafeHSJAVASCRIPT25 = `
function f() {
	try {
		const allUsers = db.users.getAll()
		return res.send(allUsers)
	} catch (err) {
		MyServerSideLogger(err.stack);
		return res.status(500);
	}
}
`
	SampleVulnerableHSJAVASCRIPT26 = `
function f() {
	const badBinary = axios.get('http://insecureDomain.com/program.bin');
	os.exec(badBinary);
}
`
	SampleSafeHSJAVASCRIPT26 = `
function f() {
	const myBinary = axios.get('https://secureDomain.com/program.exe');
	os.exec(myBinary);
}
`
	SampleVulnerableHSJAVASCRIPT27 = `
import request from 'request';

function f() {
	require request from request.body;
 	request(req.body);
}
`
	SampleSafeHSJAVASCRIPT27 = `
function f() {
	const { data } = req.body;
	const safeData = MySanitizer(data)
 	return request(safeData);
}
`
	SampleVulnerableHSJAVASCRIPT28 = `
function f({ req, res }) {
	var request = require('request');
	const res = request.get(req.body);
	return res;
}
`
	SampleSafeHSJAVASCRIPT28 = ``

	SampleVulnerableHSJAVASCRIPT29 = `
function f() {
	const myKey = crypto.generateKeyPairSync('rsa', {
		modulusLength: 1024	
	});
}
`
	SampleSafeHSJAVASCRIPT29 = `
function f() {
	const myKey = crypto.generateKeyPairSync('rsa', {
		modulusLength: 4096	
	});
}
`
	SampleVulnerableHSJAVASCRIPT30 = `
function f() {
	const myKey = crypto.generateKeyPairSync('ec', {
		namedCurve: 'secp102k1'	
	});
}
`
	SampleSafeHSJAVASCRIPT30 = `
function f() {
	const myKey = crypto.generateKeyPairSync('ec', {
		namedCurve: 'secp521k1'	
	});
}
`
	SampleVulnerableHSJAVASCRIPT31 = `
function f() {
	var jwt = require('jsonwebtoken');
	var token = jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256'});
}
`
	SampleSafeHSJAVASCRIPT31 = `
function f() {
	var jwt = require('jsonwebtoken');
	var token = jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'HS384'});
}
`
	SampleVulnerableHSJAVASCRIPT32 = `
const tls = require('tls')
tls.connect({
  checkServerIdentity: () => myCustomVerification()
})
`
	SampleSafeHSJAVASCRIPT32 = `
const tls = require('tls')
tls.connect()
`
	SampleVulnerableHSJAVASCRIPT33 = `
tls.connect({
  rejectUnauthorized: false
})
`
	SampleSafeHSJAVASCRIPT33 = `
tls.connect({
  rejectUnauthorized: true
})
`
	SampleVulnerableHSJAVASCRIPT34 = `
const element = createElement('script');
element.setAttribute('src', req.body.data)
element.setAttribute('type', 'text/javascript')
`
	SampleSafeHSJAVASCRIPT34 = ``

	SampleVulnerableHSJAVASCRIPT35 = `
var mysql = require('mysql');

var con = mysql.createConnection({
  	password: "root",
	user: "root",
  	host: "localhost",
});
`
	SampleSafeHSJAVASCRIPT35 = `
var mysql = require('mysql');

var con = mysql.createConnection({
	user: process.env.DB_USER,
	password: process.env.DB_PASS
	host: process.env.DB_HOST,
});
`
	SampleVulnerableHSJAVASCRIPT36 = `
const { exec } = require('child_process');
exec('chmod 666 /home/dev', { shell: true })
`
	SampleSafeHSJAVASCRIPT36 = ``

	SampleVulnerableHSJAVASCRIPT37 = `
import httpProxy from 'http-proxy'
function f() {
	return new httpProxy.createProxyServer({
		xfwd: true
	});
}
`
	SampleSafeHSJAVASCRIPT37 = `
import httpProxy from 'http-proxy'
function f() {
	return new httpProxy.createProxyServer({
		xfwd: false
	});
}
`
	SampleVulnerableHSJAVASCRIPT38 = `
	const { Signale } = require('signale');
	const logger = new Signale({ secrets: [] });
`
	SampleSafeHSJAVASCRIPT38 = `
	const { Signale } = require('signale');
	const regexToRemoveSensitiveData = "([0-9]{4}-?)+";
	const logger = new Signale({ secrets: [regexToRemoveSensitiveData] });
`
	SampleVulnerableHSJAVASCRIPT39 = `
const express = require('express'),
app = express();
app.use(require('helmet')({
    dnsPrefetchControl:{ allow: true }
}));
`
	SampleSafeHSJAVASCRIPT39 = `
const express = require('express'),
app = express();
app.use(require('helmet')({
    dnsPrefetchControl:{ allow: false }
}));
`
	SampleVulnerableHSJAVASCRIPT40 = `
const express = require('express'),
app = express();
app.use(require('helmet')({
    expectCt: false
}));
`
	SampleSafeHSJAVASCRIPT40 = `
const express = require('express'),
app = express();
app.use(require('helmet')({
    expectCt: true
}));
`
	SampleVulnerableHSJAVASCRIPT41 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(
  helmet({
    referrerPolicy: { policy: 'no-referrer-when-downgrade' }
  })
);
`
	SampleSafeHSJAVASCRIPT41 = `
const express = require('express'),
app = express();
app.use(require('helmet')({
    referrerPolicy: { policy: 'no-referrer' }
}));
`
	SampleVulnerableHSJAVASCRIPT42 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(
  helmet({
    noSniff: false
  })
);
`
	SampleSafeHSJAVASCRIPT42 = `
const express = require('express'),
const helmet = require('helmet');
app = express();

app.use(helmet.noSniff());

app.use(
  helmet({
    noSniff: true
  })
);
`
	SampleVulnerableHSJAVASCRIPT43 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      frameAncestors: ["'none'"],
    },
  })
);
`
	SampleSafeHSJAVASCRIPT43 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(helmet.contentSecurityPolicy());
`
	SampleVulnerableHSJAVASCRIPT44 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      blockAllMixed: ['self'],
    },
  })
);
`
	SampleSafeHSJAVASCRIPT44 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(helmet.contentSecurityPolicy());
`
	SampleVulnerableHSJAVASCRIPT45 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(
  helmet({
    contentSecurityPolicy: false
  })
);
`
	SampleSafeHSJAVASCRIPT45 = `
const express = require('express'),
const helmet = require('helmet');
app = express();
app.use(helmet.contentSecurityPolicy());
`
	SampleVulnerableHSJAVASCRIPT46 = `
const express = require('express');
const cookieSession = require('cookie-session');
app = express();
app.use(cookieSession({
	name: 'session',
	httpOnly: false
})
`
	SampleSafeHSJAVASCRIPT46 = `
const express = require('express');
const cookieSession = require('cookie-session');
app = express();
app.use(cookieSession({
	name: 'session',
	httpOnly: true
})
`
	SampleVulnerableHSJAVASCRIPT47 = `
const express = require('express');
const cookieSession = require('cookie-session');
app = express();
app.use(cookieSession({
	name: 'session',
	secure: false
})
`
	SampleSafeHSJAVASCRIPT47 = `
const express = require('express');
const cookieSession = require('cookie-session');
app = express();
app.use(cookieSession({
	name: 'session',
	secure: true
})
`
	SampleVulnerableHSJAVASCRIPT48 = `
const net = require('net');
const socket = new net.Socket();
net.connect({ port: port }, () => {});
`
	SampleSafeHSJAVASCRIPT48 = `
const express = require('express');
const app = express();
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);

io.on('connection', (socket) => {
  console.log('a user connected');
});

server.listen(3000, () => {
  console.log('listening on *:3000');
});
`
	SampleVulnerableHSJAVASCRIPT49 = `
const crypto = require('crypto');
const key = Buffer.from(crypto.randomBytes(32));
const iv = crypto.randomBytes(16);

let cipher = crypto.createCipheriv('RC4', key, iv);
`
	SampleSafeHSJAVASCRIPT49 = `
const crypto = require('crypto');
const key = Buffer.from(crypto.randomBytes(32));
const iv = crypto.randomBytes(16);

let cipher = crypto.createCipheriv('AES-256-GCM', key, iv);
`
	SampleVulnerableHSJAVASCRIPT50 = `
const Formidable = require('formidable');
const form = new Formidable();
form.keepExtensions = true;
`
	SampleSafeHSJAVASCRIPT50 = `
const Formidable = require('formidable');
const form = new Formidable();
form.keepExtensions = false;
`
	SampleVulnerableHSJAVASCRIPT51 = `
const Formidable = require('formidable');
const form = new Formidable();
form.maxFileSize = 10000000;
`
	SampleSafeHSJAVASCRIPT51 = `
const Formidable = require('formidable');
const form = new Formidable();
form.maxFileSize = 7000000;
`
	SampleVulnerableHSJAVASCRIPT52 = `
function f1() {
	let Mustache = require("mustache");
	Mustache.escape = function(text) {return text;};
	let rendered = Mustache.render(template, { name: inputName });
}

function f2() {
const markdownIt = require('markdown-it');
let md = markdownIt({
	html: true
});

let result = md.render('# <b>attack</b>');
}
`
	SampleSafeHSJAVASCRIPT52 = `
function f1() {
	let Mustache = require("mustache");
	let rendered = Mustache.render(template, { name: inputName });
}

function f2() {
const markdownIt = require('markdown-it');
let result = md.render('# <b>attack</b>');
}
`
	SampleVulnerableHSJAVASCRIPT53 = `
const db = require('./mysql/dbConnection.js');
const email = req.query.email;
db.query("SELECT * FROM USERS WHERE EMAIL = " + name);
`
	SampleSafeHSJAVASCRIPT53 = `
var query = "";
const db = require('./mysql/dbConnection.js');
const email = req.query.email;
db.query("SELECT * FROM USERS WHERE EMAIL = ?", [email]);
`
	SampleVulnerableHSJAVASCRIPT54 = `
const MongoClient = require('mongodb').MongoClient;
MongoClient.connect("mongodb://localhost:27017/mydb", function(err, db) {
  if (err) throw err;
  db.close();
});
`
	SampleSafeHSJAVASCRIPT54 = `
const MongoClient = require('mongodb').MongoClient;
MongoClient.connect(process.env.MONGO_URI, function(err, db) {
  if (err) throw err;
  db.close();
});
`

	SampleVulnerableHSJAVASCRIPT55 = `
const { Client } = require('pg')
const client = new Client({
	password: 'root',
	user: 'root',
	host: 'localhost',
})
`
	SampleSafeHSJAVASCRIPT55 = `
const { Client } = require('pg')
const client = new Client({
	user: process.env.DB_USER,
	password: process.env.DB_PASS
	host: process.env.DB_HOST,
`
)
