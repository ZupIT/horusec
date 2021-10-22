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

package dart

const (
	SampleVulnerableDartSendSMS = `import 'package:flutter_sms/flutter_sms.dart';
`
	SampleVulnerableUsageLocalDataWithoutCryptography = `
...
final CpfExposedFromUserInput = "";
...
void onButtonClick() async {
	try {
		var value = await ValidateCPFPost(CpfExposedFromUserInput)
		SharedPreferences prefs = await SharedPreferences.getInstance();

		// Possible Vulnerable Code: exposed identity of the user in local machine
		prefs.setString('cpf', CpfExposedFromUser);
		...
	} on HttpException {
		...
	}
}
...
`
	SampleVulnerableNoSendSensitiveInformation = `
...
  FirebaseMessaging _firebaseMessaging = FirebaseMessaging();
  
  @override
  void initState() {
    ...
    super.initState();
    _firebaseMessaging.configure(
      // Possible vulnerable code: exposed sensitive information on application log or in notification of the user
      onMessage: (Map<String, dynamic> response) async {
        print("onMessage: $response");
        ...
      },
      onLaunch: (Map<String, dynamic> response) async {
        print("onLaunch: $response");
        ...
      },
      onResume: (Map<String, dynamic> response) async {
        print("onResume: $response");
        ...
      },
    );
  }
...
`
	SampleVulnerableNoUseBiometricsTypeIOS = `
List<BiometricType> availableBiometrics;
    await auth.getAvailableBiometrics();

if (Platform.isIOS) {
    if (availableBiometrics.contains(BiometricType.face)) {
        // Face ID.
    } else if (availableBiometrics.contains(BiometricType.fingerprint)) {
        // Touch ID.
    }
}
`
	SampleVulnerableXmlReaderExternalEntityExpansion = `
// Possible vulnerable code: user can pass other path in your input and causes attacks in the application.
final file = new File(FileFromUserInput);
final document = XmlDocument.parse(file.readAsStringSync());
`
	SampleVulnerableNoUseConnectionWithoutSSL = `
...
static Future<HttpServer> SentToApi(
	int port,
	SecurityContext context,
	{int backlog = 0,
	bool v6Only = false,
	bool requestClientCertificate = false,
	bool shared = false}
) {
    // Possible vulnerable code: HTTP without SSL is not secure. 
    return _HttpServer.bindSecure('http://my-api.com.br', port, context, backlog, v6Only, requestClientCertificate, shared);
}
`
)

const (
	SampleSafeUsageLocalDataWithoutCryptography = `
...
final CpfExposedFromUserInput = "";
...
void onButtonClick() async {
	try {
        // Safe code: Because not log information sensitive and only sent to backend api. 
		var value = await ValidateCPFPost(CpfExposedFromUserInput)
		...
	} on HttpException {
		...
	}
}
...
`
	SampleSafeNoSendSensitiveInformation = `
...
  FirebaseMessaging _firebaseMessaging = FirebaseMessaging();
  
  @override
  void initState() {
    ...
    super.initState();
    // Safe code: Because not log information sensitive and only sent to backend api.
    _firebaseMessaging.configure(
      onLaunch: (Map<String, dynamic> response) async {
        sendToAPI(response);
        ...
      },
    );
  }
...
`
	SampleSafeXmlReaderExternalEntityExpansion = `
final file = new File('static-file.xml');
final document = XmlDocument.parse(file.readAsStringSync());
`

	SampleSafeNoUseConnectionWithoutSSL = `
static Future<HttpServer> SentToApi(
	int port,
	SecurityContext context,
	{int backlog = 0,
	bool v6Only = false,
	bool requestClientCertificate = false,
	bool shared = false}
) => _HttpServer.bindSecure('https://my-api.com.br', port, context, backlog, v6Only, requestClientCertificate, shared);
`
)
