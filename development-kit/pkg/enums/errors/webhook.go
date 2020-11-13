package errors

import "errors"

var ErrorAlreadyExistsWebhookToRepository = errors.New("already exists webhook to repository selected")

const ErrorAlreadyExistingRepositoryIDInWebhook = "pq: duplicate key value violates unique constraint" +
	" \"webhooks_repository_id_key\""
