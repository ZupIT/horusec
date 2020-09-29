FROM golang:1.14-alpine

RUN apk update && apk upgrade \
	&& apk add jq curl

RUN set -o pipefail && curl https://api.github.com/repos/liamg/tfsec/releases/latest | jq -r ".assets[] | select(.name | contains(\"tfsec-linux-amd64\")) | .browser_download_url" | xargs wget

RUN mv tfsec-linux-amd64 /bin/tfsec

RUN chmod +x /bin/tfsec

CMD ["/bin/sh"]