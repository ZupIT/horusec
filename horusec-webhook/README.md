# HORUSEC-WEBHOOK
This service is responsible for dispatch http request to destiny configured in horusec database. 

You can see more details about this service in image <a href="../assets/horusec-webhook.jpg">/assets/horusec-webhook.jpg</a>

## Running
To run the service you can run the follow command
```bash
go run ./horusec-webhook/cmd/app/main.go
```

And you see the log
```bash
service running on port :8008
swagger running on url:  http://localhost:8008/swagger/index.html
```

## Environments
To change variables environment to run your analysis also you set new values.

| Environment Name                              | Default Value                                                                              | Description                                                  |
|-----------------------------------------------|--------------------------------------------------------------------------------------------|--------------------------------------------------------------|
| HORUSEC_SWAGGER_HOST                          | 0.0.0.0                                                                                    | This environment get host to run in swagger                  |
| HORUSEC_BROKER_HOST                           | 127.0.0.1                                                                                  | This environment get host to connect on broker RABBIT        | 
| HORUSEC_BROKER_PORT                           | 5672                                                                                       | This environment get port to connect on broker RABBIT        |
| HORUSEC_BROKER_USERNAME                       | guest                                                                                      | This environment get username to connect on broker RABBIT    |
| HORUSEC_BROKER_PASSWORD                       | guest                                                                                      | This environment get password to connect on broker RABBIT    |
| HORUSEC_DATABASE_SQL_URI                      | postgresql://root:root@localhost:5432/horusec_db?sslmode=disable                           | This environment get uri to connect on database POSTGRES     |
| HORUSEC_DATABASE_SQL_DIALECT                  | postgres                                                                                   | This environment get dialect to connect on database POSTGRES |
| HORUSEC_DATABASE_SQL_LOG_MODE                 | false                                                                                      | This environment get bool to enable logs on POSTGRES         |
| HORUSEC_PORT                                  | 8008                                                                                       | This environment get the port that the service will start    |
| HORUSEC_HTTP_TIMEOUT                          | 60                                                                                         | This environment get the time in seconds for wait response of request http |

## Swagger
To update swagger.json, you need run command into **root horusec-webhook folder**
```bash
swag init -g ./cmd/app/main.go
```
