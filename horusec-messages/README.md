# HORUSEC-MESSAGES
This is the transaction email messages service of Horusec.

The service should be able to receive a package from the message broker and then
dispatch a smtp email message to horusec user.

[What is transactional email and what is it used for?](https://postmarkapp.com/blog/what-is-transactional-email-and-how-is-it-used)

You can see more details about this service in image <a href="../assets/horusec-messages.jpg">/assets/horusec-messages.jpg</a>

## Running
To run the service you can run the follow command
```bash
go run ./horusec-messages/cmd/app/main.go
```

And you see the log
```bash
service running on port :8004
swagger running on url:  http://localhost:8004/swagger/index.html
```

## Generate new version
To generate a new version go to the root directory you can run the follow command, and it will generate a new version on `dokerhub`.
```bash
make update-messages
```

## Environments
To change variables environment to run your analysis also you set new values.

| Environment Name                            | Default Value         | Description                  |
|---------------------------------------------|-----------------------|------------------------------|
| HORUSEC_BROKER_HOST                           | 127.0.0.1             | This environment get host to connect on broker RABBIT | 
| HORUSEC_BROKER_PORT                           | 5672                  | This environment get port to connect on broker RABBIT |
| HORUSEC_BROKER_USERNAME                       | guest                 | This environment get username to connect on broker RABBIT |
| HORUSEC_BROKER_PASSWORD                       | guest                 | This environment get password to connect on broker RABBIT |
| HORUSEC_SMTP_USERNAME                         |                       | This environment get username to connect on mailer. Example using gsuite host `user@gmail.com` |
| HORUSEC_SMTP_PASSWORD                         |                       | This environment get password to connect on mailer. Example using gsuite host `Y0urS!r0ng#P@ssw0rd` |
| HORUSEC_SMTP_ADDRESS                          |                       | This environment get address to connect on mailer. Example using gsuite host `smtp.gmail.com` |
| HORUSEC_SMTP_HOST                             |                       | This environment get host to connect on mailer. Example using gsuite host `smtp.gmail.com` |
| HORUSEC_SMTP_PORT                             |                       | This environment get port to connect on mailer. Example using gsuite host `587` |
| HORUSEC_EMAIL_FROM                            | horusec@zup.com.br      | This environment get email of the user origin to send email. If You using other email to send, change here. |
| HORUSEC_PORT                                  | 8004                  | This environment get the port that the service will start |
| HORUSEC_SWAGGER_HOST                          | localhost             | This environment get the host for swagger start |

### Emails triggers

| Trigger             | Description |
|---------------------|-------------|
| email confirmation  | An email that are used for user email confirmation |
| reset password      | An email that allows user to reset your own password |
| organization invite | An email to inform an user that he was invited for an organization |

## Swagger
To update swagger.json, you need run command into **root horusec-messages folder**
```bash
swag init -g ./cmd/app/main.go
```

