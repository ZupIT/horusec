# HORUSEC-ACCOUNT
This service is responsible for user authentication and management, as well as which companies and repositories it owns or has access to. 

You can see more details about this service in image <a href="../assets/horusec-account.jpg">/assets/horusec-account.jpg</a>

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
go run ./horusec-account/cmd/app/main.go
```

And you see the log
```bash
service running on port :8003
swagger running on url:  http://localhost:8003/swagger/index.html
```

## Generate new version
To generate a new version go to the root directory you can run the follow command, and it will generate a new version on `dokerhub`.
```bash
make update-account
```

## Environments
To change variables environment to run your analysis also you set new values.

| Environment Name                              | Default Value                                                    | Description                                                  |
|-----------------------------------------------|------------------------------                                    |--------------------------------------------------------------|
| HORUSEC_SWAGGER_HOST                          | 0.0.0.0                                                          | This environment get host to run in swagger                  |
| HORUSEC_API_URL                               | http://localhost:8003                                            | This environment get horusec url to mount a url              | 
| HORUSEC_MANAGER_URL                           | http://localhost:8043                                            | This environment get horusec url to mount a url              | 
| HORUSEC_BROKER_HOST                           | 127.0.0.1                                                        | This environment get host to connect on broker RABBIT        | 
| HORUSEC_BROKER_PORT                           | 5672                                                             | This environment get port to connect on broker RABBIT        |
| HORUSEC_BROKER_USERNAME                       | guest                                                            | This environment get username to connect on broker RABBIT    |
| HORUSEC_BROKER_PASSWORD                       | guest                                                            | This environment get password to connect on broker RABBIT    |
| HORUSEC_DATABASE_SQL_URI                      | postgresql://root:root@localhost:5432/horusec_db?sslmode=disable | This environment get uri to connect on database POSTGRES     |
| HORUSEC_DATABASE_SQL_DIALECT                  | postgres                                                         | This environment get dialect to connect on database POSTGRES |
| HORUSEC_DATABASE_SQL_LOG_MODE                 | false                                                            | This environment get bool to enable logs on POSTGRES         |
| HORUSEC_PORT                                  | 8003                                                             | This environment get the port that the service will start    |
| HORUSEC_JWT_SECRET_KEY                        | horusec-secret                                                   | This environment get JWT secret key                          | 
| HORUSEC_ACCOUNT_DISABLE_EMAIL_SERVICE         | false                                                            | Disable email confirmation on user register                  | 
| HORUSEC_AUTH_URL                              | http://localhost:8006                                            | This environment get horusec url to mount horusec auth url   |

## Swagger
To update swagger.json, you need run command into **root horusec-account folder**
```bash
swag init -g ./cmd/app/main.go
```
