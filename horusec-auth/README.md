# HORUSEC-AUTH
Service responsible for performing login according to the type of authentication specified, as well as validating requests.

You can see more details about this service in image <a href="../assets/horusec-auth.jpg">/assets/horusec-auth.jpg</a>

##Migrations
On horusec we use [GORM](https://gorm.io/) to manage our database. 

To run the migrations use the following command in root directory of the horusec.
If you need change host or username or password or port you can change inside this file in your global variables:

```bash
deployments/scripts/migration-run.sh up
```

## Running
To run the service you can run the follow command
```bash
go run ./horusec-auth/cmd/app/main.go
```

You will see the log
```bash
service running on port :8006
swagger running on url:  http://localhost:8006/swagger/index.html
```

## Environments
To change variables environment to run your analysis also you set new values.

| Environment Name                    | Default Value                                                     | Description                                                  |
|-------------------------------------|-------------------------------------------------------------------|--------------------------------------------------------------|
| HORUSEC_SWAGGER_HOST                | http://0.0.0.0:8006                                               | This environment get host to run in swagger                  |
| HORUSEC_DATABASE_SQL_URI            | postgresql://root:root@localhost:5432/horusec_db?sslmode=disable  | This environment get uri to connect on database POSTGRES     |
| HORUSEC_DATABASE_SQL_DIALECT        | postgres                                                          | This environment get dialect to connect on database POSTGRES |
| HORUSEC_DATABASE_SQL_LOG_MODE       | false                                                             | This environment get bool to enable logs on POSTGRES         | 
| HORUSEC_BROKER_HOST                 | 127.0.0.1                                                         | This environment get host to connect on broker RABBIT        | 
| HORUSEC_BROKER_PORT                 | 5672                                                              | This environment get port to connect on broker RABBIT        |
| HORUSEC_BROKER_USERNAME             | guest                                                             | This environment get username to connect on broker RABBIT    |
| HORUSEC_BROKER_PASSWORD             | guest                                                             | This environment get password to connect on broker RABBIT    |
| HORUSEC_PORT                        | 8006                                                              | This environment get the port that the service will start    |
| HORUSEC_AUTH_TYPE                   | horusec                                                           | This environment get actual authentication type              |
| HORUSEC_JWT_SECRET_KEY              | horusec-secret                                                    | This environment get JWT secret key                          | 
| HORUSEC_KEYCLOAK_BASE_PATH          |                                                                   | This environment get keycloak base path                      | 
| HORUSEC_KEYCLOAK_CLIENT_ID          |                                                                   | This environment get keycloak client id                      | 
| HORUSEC_KEYCLOAK_CLIENT_SECRET      |                                                                   | This environment get keycloak client secret                  | 
| HORUSEC_KEYCLOAK_REALM              |                                                                   | This environment get keycloak realm                          |
| HORUSEC_KEYCLOAK_OTP                |                                                                   | This environment get keycloak otp(one-time password)         | 
| HORUSEC_LDAP_HOST                   |                                                                   | This environment get ldap host | 
| HORUSEC_LDAP_PORT                   | 389                                                               | This environment get ldap port |
| HORUSEC_LDAP_BASE                   |                                                                   | This environment get ldap base | 
| HORUSEC_LDAP_BINDDN                 |                                                                   | This environment get ldap entity admin | 
| HORUSEC_LDAP_BINDPASSWORD           |                                                                   | This environment get ldap password entity admin | 
| HORUSEC_LDAP_USERFILTER             | (sAMAccountName=%s)                                               | This environment get ldap user filter | 
| HORUSEC_LDAP_ADMIN_GROUP            |                                                                   | This environment get ldap admin group names |
| HORUSEC_LDAP_USESSL                 | false                                                             | This environment check ldap use ssl | 
| HORUSEC_LDAP_SKIP_TLS               | true                                                              | This environment check ldap skip tls | 
| HORUSEC_LDAP_INSECURE_SKIP_VERIFY   | true                                                              | This environment check ldap insecure skip verify |
| HORUSEC_GRPC_PORT                   | 8007                                                              | This environment get grpc port                               | 
| HORUSEC_GRPC_USE_CERTS              | false                                                             | This environment get if use of certificates is active or not |
| HORUSEC_GRPC_CERT_PATH              |                                                                   | This environment get grpc certificate path                   | 
| HORUSEC_GRPC_KEY_PATH               |                                                                   | This environment get grpc certificate key path               | 
| HORUSEC_ENABLE_APPLICATION_ADMIN    | false                                                             | This environment set if you need active application admin in system. When this environment is setup to `true` only application admin users can create company in horusec. | 
| HORUSEC_APPLICATION_ADMIN_DATA      | {\"username\": \"horusec-admin\", \"email\":\"horusec-admin@example.com\", \"password\":\"Devpass0*\"} | When application admin is enable and auth-type is `horusec` we need create default user application admin with this content in horusec. Don't forget to **escape the json** at the value of the environment variable. | 
| HORUSEC_DISABLED_BROKER             | false                                                             | Disable broker dispatch in this service used to emails dispatch |
| HORUSEC_API_URL                     | http://localhost:8003                                             | This environment get horusec-api endpoint |

## Swagger
To update swagger.json, you need run command into **root horusec-auth folder**
```bash
swag init -g ./cmd/app/main.go
```
