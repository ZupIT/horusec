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

package jvm

const (
	SampleVulnerableHSJVM38 = `
class T {
	void f() {
		String input = "test input";
		Base64.getEncoder().encodeToString(input.getBytes());

		Base64 base64 = new Base64();
		String encodedString = new String(base64.encode(input.getBytes()));
	}
}
	`

	SampleVulnerableHSJVM24 = `
class T {
	void f(String value) {
		byte[] decodedValue = Base64.getDecoder().decode(value);
	}
}
	`
)

const (
	SampleSafeHSJVM38 = `
class T {
	void f() {
		obj.addContentType("application/x-www-form-urlencoded")
	}
}
	`
	Sample2SafeHSJVM38 = `
<encoder class="net.logstash.logback.encoder.AccessEventCompositeJsonEncoder">"
<encoder class="net.logstash.logback.encoder.LoggingEventCompositeJsonEncoder">

<encoder>
</encoder>
`

	SampleSafeHSJVM24 = `
class T {
	void f() {
		this.decodeSomeRandomValue("value);
		console.log.println("foo.decode");
	}

	void decodeSomeRandomValue(String value) {}
}
`
)
