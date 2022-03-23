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

package leaks

const (
	SampleVulnerableHSLEAKS1 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	    ACCESS_KEY: 'AKIAJSIE27KKMHXI3BJQ'
`
	SampleSafeHSLEAKS1 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  ACCESS_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS2 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      AWS_SECRET_KEY: 'doc5eRXFpsWllGC5yKJV/Ymm5KwF+IRZo95EudOm'
	`
	SampleSafeHSLEAKS2 = `
	version: '3'
	services:
		backend:
			image: image/my-backend:latest
			environment:
			SECRET_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS3 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      AWS_WMS_KEY: 'amzn.mws.986478f0-9775-eabc-2af4-e499a8496828'
`
	SampleSafeHSLEAKS3 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      WMS_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS4 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      FB_SECRET_KEY: 'cb6f53505911332d30867f44a1c1b9b5'
`
	SampleSafeHSLEAKS4 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  FB_SECRET_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS5 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      FB_CLIENT_ID: '148695999071979'
`
	SampleSafeHSLEAKS5 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  FB_CLIENT_ID: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS6 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      TWITTER_SECRET_KEY: 'ej64cqk9k8px9ae3e47ip89l7if58tqhpxi1r'
`
	SampleSafeHSLEAKS6 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  TWITTER_SECRET_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS7 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      TWITTER_CLIENT_ID: '1h6433fsvygnyre5a40'
`
	SampleSafeHSLEAKS7 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  TWITTER_CLIENT_ID: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS8 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      GITHUB_SECRET_KEY: 'edzvPbU3SYUc7pFc9le20lzIRErTOaxCABQ1'
`
	SampleSafeHSLEAKS8 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  GITHUB_SECRET_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS9 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      LINKEDIN_CLIENT_ID: 'g309xttlaw25'
`
	SampleSafeHSLEAKS9 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  LINKEDIN_CLIENT_ID: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS10 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      LINKEDIN_SECRET_KEY: '0d16kcnjyfzmcmjp'
`
	SampleSafeHSLEAKS10 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  LINKEDIN_SECRET_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS11 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SLACK_WEBHOOK: 'https://hooks.slack.com/services/TNeqvYPeO/BncTJ74Hf/NlvFFKKAKPkd6h7FlQCz1Blu'
`
	SampleSafeHSLEAKS11 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SLACK_WEBHOOK: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS12 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SSH_PRIVATE_KEY: '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDBj08sp5++4anGcmQxJjAkBgNVBAoTHVByb2dyZXNzIFNvZnR3YXJlIENvcnBvcmF0aW9uMSAwHgYDVQQDDBcqLmF3cy10ZXN0LnByb2dyZXNzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD...bml6YXRpb252YWxzaGEyZzIuY3JsMIGgBggrBgEFBQcBAQSBkzCBkDBNBggrBgEFBQcwAoZBaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nvcmdhz3P668YfhUbKdRF6S42Cg6zn-----END PRIVATE KEY-----'
`
	SampleSafeHSLEAKS12 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SSH_PRIVATE_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS13 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      GCP_API_KEY: 'AIzaMPZHYiu1RdzE1nG2SaVyOoz244TuacQIR6m'
`
	SampleSafeHSLEAKS13 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  GCP_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS14 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      GCP_SERVICE_ACCOUNT: '18256698220617903267772185514630273595-oy8_uzouz8tyy46y84ckrwei9_6rq_pb.apps.googleusercontent.com'
`
	SampleSafeHSLEAKS14 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  GCP_SERVICE_ACCOUNT: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS15 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      HEROKU_API_KEY: '3623f8e9-2d05-c9bb-2209082d6b5c'
`
	SampleSafeHSLEAKS15 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  HEROKU_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS16 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      MAILCHIMP_API_KEY: 'f7e9c13c10d0b19c3bb003a9f635d488-us72'
`
	SampleSafeHSLEAKS16 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  MAILCHIMP_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS17 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      MAILGUN_API_KEY: 'key-xke9nbc2i5po5cjw3ngyxiz450zxpapu'
`
	SampleSafeHSLEAKS17 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  MAILGUN_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS18 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      PAY_PAL_ACCESS_TOKEN: 'access_token$production$mk0sech2v7qqsol3$db651af2221c22b4ca2f0f583798135e'
`
	SampleSafeHSLEAKS18 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  PAY_PAL_ACCESS_TOKEN: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS19 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      PICATIC_API_KEY: 'sk_live_voy1p9k7r9g9j8ezmif488nk2p8310nl'
`
	SampleSafeHSLEAKS19 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  PICATIC_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS20 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SEND_GRID_API_KEY: 'SG.44b7kq3FurdH0bSHBGjPSWhE8vJ.1evu4Un0TXFIb1_6zW4YOdjTMeE'
`
	SampleSafeHSLEAKS20 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SEND_GRID_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS21 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      STRIPE_API_KEY: 'rk_live_8qSZpoI9t0BOGkOLVzvesc6K'
`
	SampleSafeHSLEAKS21 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  STRIPE_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS22 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SQUARE_ACCESS_TOKEN: 'sq0atp-clYRBSht6oefa7w_2R56ra'
`
	SampleSafeHSLEAKS22 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SQUARE_ACCESS_TOKEN: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS23 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      SQUARE_SECRET: 'sq0csp-LsEBYQNja]OgT3hRxjJV5cWX^XjpT12n3QkRY_vep2z'
`
	SampleSafeHSLEAKS23 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  SQUARE_SECRET: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS24 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      TWILIO_API_KEY: '^SK9ae6bd84ccd091eb6bfad8e2a474af95'
`
	SampleSafeHSLEAKS24 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  TWILIO_API_KEY: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS25 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
      POSTGRES_DBPASSWD: 'Ch@ng3m3'
`

	SampleSafeHSLEAKS25 = `
version: '3'
services:
  backend:
    image: image/my-backend:latest
    environment:
	  POSTGRES_DBPASSWD: ${SECRET_KEY}
`

	SampleVulnerableHSLEAKS26 = `
package main

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	DB_USER="gorm"
	DB_PASSWORD="gorm"
	DB_NAME="gorm"
	DB_PORT="9920"
  	dsn := fmt.Sprintf("user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai", DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`
	SampleSafeHSLEAKS26 = `
package main

import (
  "os"
  "fmt"
  "gorm.io/gorm"
  "gorm.io/driver/postgres"
)

func main() {
	DB_USER="gorm"
	DB_PASSWORD=os.Getenv("DB_PASSWORD")
	DB_NAME="gorm"
	DB_PORT="9920"
  	dsn := fmt.Sprintf("user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai", DB_USER, DB_PASSWORD, DB_NAME, DB_PORT)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`
	SampleVulnerableHSLEAKS27 = `
package main

import (
  "gorm.io/gorm"
  "gorm.io/driver/postgres"
)

func main() {
	dsn := "postgresql://gorm:gorm@127.0.0.1:5432/gorm?sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`
	SampleSafeHSLEAKS27 = `
package main

import (
  "os"
  "gorm.io/gorm"
  "gorm.io/driver/postgres"
)

func main() {
	dsn := os.Getenv("DB_QUERY_STRING")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	print(db)
}
`

	SampleVulnerableHSLEAKS28 = `
	<?php
define('AUTH_KEY', 'put your unique phrase here');
define('DB_PASSWORD', 'wen0221!');
`

	SampleSafeHSLEAKS28 = `
<?php
define('AUTH_KEY', getenv("AUTH_KEY"));
`
)
