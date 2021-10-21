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

package nginx

const (
	SampleVulnerableIncludeXContentTypeOptionsHeader = `
add_header X-Frame-Options "SAMEORIGIN";
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'; img-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'";
upstream plone52 {
    server 127.0.0.1:8080;
}`
	SampleSafeIncludeXContentTypeOptionsHeader = `
add_header X-Frame-Options "SAMEORIGIN";
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
add_header X-Content-Type-Options "nosniff";
add_header Content-Security-Policy "default-src 'self'; img-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'";
upstream plone52 {
    server 127.0.0.1:8080;
}`
	SampleVulnerableIncludeXFrameOptionsHeader = `
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'; img-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'";
upstream plone52 {
    server 127.0.0.1:8080;
}`
	SampleSafeIncludeXFrameOptionsHeader = `
add_header X-Frame-Options "SAMEORIGIN";
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'; img-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'";
upstream plone52 {
    server 127.0.0.1:8080;
}`
	SampleVulnerableIncludeContentSecurityPolicyHeader = `
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
upstream plone52 {
    server 127.0.0.1:8080;
}`
	SampleSafeIncludeContentSecurityPolicyHeader = `
add_header X-Frame-Options "SAMEORIGIN";
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'; img-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'";
upstream plone52 {
    server 127.0.0.1:8080;
}`
	SampleVulnerableIncludeServerTokensOff = `
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
upstream plone52 {
    server 127.0.0.1:8080;
}`
	SampleSafeIncludeServerTokensOff = `
server_tokens off;
add_header X-Frame-Options "SAMEORIGIN";
add_header Strict-Transport-Security "max-age=15768000; includeSubDomains";
add_header X-XSS-Protection "1; mode=block";
add_header Content-Security-Policy "default-src 'self'; img-src *; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'";
upstream plone52 {
    server 127.0.0.1:8080;
}`
)
