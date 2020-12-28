printf 'Generating Certs            ...'
rm -rf .env

if [ ! -f api/api-tls-cert.pem ] && [ ! -f api/api-tls-key.pem ]; then
    rm -rf deployments/certs/*
    ./deployments/scripts/create-certs.sh -m ca -pw "horusCertPassphrase" -t deployments/certs -e 900
    ./deployments/scripts/create-certs.sh -m server -h dockerapi -pw "horusCertPassphrase" -t deployments/certs -e 365
    ./deployments/scripts/create-certs.sh -m client -h horusapi -pw "horusCertPassphrase" -t deployments/certs -e 365
    ./deployments/scripts/create-certs.sh -m tls -h dockerapi -pw "horusCertPassphrase" -t api -e 365
fi

echo " done"
