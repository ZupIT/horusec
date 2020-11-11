package errors

import "errors"

var ErrorAlreadyExistsWebhookToRepository = errors.New("already exists webhook to repository selected")

const ErrorAlreadyExistingRepositoryIDInWebhook = "pq: duplicate key value violates unique constraint" +
	" \"webhook_repository_repository_id_webhook_id_key\""
