# HORUSEC-API
Horusec-API is responsible for receiving Horusec-CLI requests via http request to start a new analysis. In addition to being responsible for acquiring and returning the analysis saved in the system!

This service will have two features:

* Receive a new code analysis:
    * Acquire zip file sent by HORUSEC-CLI;
    * Unzip and save in shared volume;
    * Perform a language detection and which language should run;
    * Publish to the HORUSEC-ANALYSER queue to start performing vulnerability detection.
* Check if the analysisID exists in the database and return your model.

You can see more details about this service in image <a href="../assets/horusec-api.jpg">/assets/horusec-api.jpg</a>

## Running
To run the service you can run the follow command
```bash
go run ./horusec-api/cmd/app/main.go
```

And you see the log
```bash
service running on port :8000
swagger running on url:  http://localhost:8000/swagger/index.html
```

## Generate new version
To generate a new version go to the root directory you can run the follow command, and it will generate a new version on `dokerhub`.
```bash
make update-api
```

## Environments
To change variables environment to run your analysis also you set new values.

| Environment Name                              | Default Value                                                    | Description                                                  |
|-----------------------------------------------|------------------------------------------------------------------|--------------------------------------------------------------|
| HORUSEC_SWAGGER_HOST                          | localhost                                                        | This environment get host to run in swagger                  | 
| HORUSEC_BROKER_HOST                           | 127.0.0.1                                                        | This environment get host to connect on broker RABBIT        | 
| HORUSEC_BROKER_PORT                           | 5672                                                             | This environment get port to connect on broker RABBIT        |
| HORUSEC_BROKER_USERNAME                       | guest                                                            | This environment get username to connect on broker RABBIT    |
| HORUSEC_BROKER_PASSWORD                       | guest                                                            | This environment get password to connect on broker RABBIT    |
| HORUSEC_DATABASE_SQL_URI                      | postgres                                                         | This environment get uri to connect on database POSTGRES     |
| HORUSEC_DATABASE_SQL_DIALECT                  | postgresql://root:root@localhost:5432/horusec_db?sslmode=disable | This environment get dialect to connect on database POSTGRES |
| HORUSEC_DIRECTORY_SAVE_ANALYSIS               | /horusec                                                         | This environment get directory path on the volume shared     | 
| HORUSEC_PORT                                  | 8000                                                             | This environment get the port that the service will start    |
| HORUSEC_SWAGGER_HOST                          | localhost                                                        | This environment get the host for swagger start              |
| HORUSEC_JWT_SECRET_KEY                        | horusec-secret                                                   | This environment get JWT secret key                          | 
| HORUSEC_AUTH_URL                              | http://localhost:8006                                            | This environment get horusec url to mount horusec auth url   |

## Swagger
To update swagger.json, you need run command into **root horusec-api folder**
```bash
swag init -g ./cmd/app/main.go
```
