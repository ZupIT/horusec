EXPIRATIONDAYS=700
CASUBJSTRING="/C=GB/ST=London/L=London/O=ExampleCompany/OU=IT/CN=example.com/emailAddress=test@example.com"

while [[ $# -gt 1 ]]
do
key="$1"

case $key in
    -m|--mode)
    MODE="$2"
    shift
    ;;
    -h|--hostname)
    NAME="$2"
    shift
    ;;
    -hip|--hostip)
    SERVERIP="$2"
    shift
    ;;
    -pw|--password)
    PASSWORD="$2"
    shift
    ;;
    -t|--targetdir)
    TARGETDIR="$2"
    shift
    ;;
    -e|--expirationdays)
    EXPIRATIONDAYS="$2"
    shift
    ;;
    --ca-subj)
    CASUBJSTRING="$2"
    shift
    ;;
    *)
            # unknown option
    ;;
esac
shift
done

echo "Mode $MODE"
echo "Host/Clientname $NAME"
echo "Host IP $SERVERIP"
echo "Targetdir $TARGETDIR"
echo "Expiration $EXPIRATIONDAYS"

programname=$0

function usage {
    echo "usage: $programname -m ca -h example.de [-hip 1.2.3.4] -pw my-secret -t /target/dir [-e 365]"
    echo "  -m|--mode                 'ca' to create CA, 'server' to create server cert, 'client' to create client cert"
    echo "  -h|--hostname|-n|--name   DNS hostname for the server or name of client"
    echo "  -hip|--hostip             host's IP - default: none"
    echo "  -pw|--password            Password for CA Key generation"
    echo "  -t|--targetdir            Targetdir for certfiles and keys"
    echo "  -e|--expirationdays       certificate expiration in day - default: 700 days"
    echo "  --ca-subj                 subj string for ca cert - default: Example String..."
    exit 1
}

function createCA {
    openssl genrsa -aes256 -passout pass:$PASSWORD -out $TARGETDIR/ca-key.pem 4096
    openssl req -passin pass:$PASSWORD -new -x509 -days $EXPIRATIONDAYS -key $TARGETDIR/ca-key.pem -sha256 -out $TARGETDIR/ca.pem -subj $CASUBJSTRING

    chmod 0400 $TARGETDIR/ca-key.pem
    chmod 0444 $TARGETDIR/ca.pem
}

function checkCAFilesExist {
    if [[ ! -f "$TARGETDIR/ca.pem" || ! -f "$TARGETDIR/ca-key.pem" ]]; then
        echo "$TARGETDIR/ca.pem or $TARGETDIR/ca-key.pem not found. Create CA first with '-m ca'"
        exit 1
    fi
}

function createTLSCert {
    openssl req -x509 -newkey rsa:4096 -keyout $TARGETDIR/api-tls-key.pem -out $TARGETDIR/api-tls-cert.pem -days 365 -nodes -subj '/CN=localhost'
}

function createServerCert {
    checkCAFilesExist

    if [[ -z $SERVERIP ]]; then
        IPSTRING=""
    else
        IPSTRING=",IP:$SERVERIP"
    fi

    openssl genrsa -out $TARGETDIR/server-key.pem 4096
    openssl req -subj "/CN=$NAME" -new -key $TARGETDIR/server-key.pem -out $TARGETDIR/server.csr
    echo "subjectAltName = DNS:$NAME$IPSTRING" > $TARGETDIR/extfile.cnf
    openssl x509 -passin pass:$PASSWORD -req -days $EXPIRATIONDAYS -in $TARGETDIR/server.csr -CA $TARGETDIR/ca.pem -CAkey $TARGETDIR/ca-key.pem -CAcreateserial -out $TARGETDIR/server-cert.pem -extfile $TARGETDIR/extfile.cnf

    rm $TARGETDIR/server.csr $TARGETDIR/extfile.cnf $TARGETDIR/ca.srl
    chmod 0400 $TARGETDIR/server-key.pem
    chmod 0444 $TARGETDIR/server-cert.pem
}

function createClientCert {
    checkCAFilesExist

    openssl genrsa -out $TARGETDIR/client-key.pem 4096
    openssl req -subj "/CN=$NAME" -new -key $TARGETDIR/client-key.pem -out $TARGETDIR/client.csr
    echo "extendedKeyUsage = clientAuth" > $TARGETDIR/extfile.cnf
    openssl x509 -passin pass:$PASSWORD -req -days $EXPIRATIONDAYS -in $TARGETDIR/client.csr -CA $TARGETDIR/ca.pem -CAkey $TARGETDIR/ca-key.pem -CAcreateserial -out $TARGETDIR/client-cert.pem -extfile $TARGETDIR/extfile.cnf

    rm $TARGETDIR/client.csr $TARGETDIR/extfile.cnf $TARGETDIR/ca.srl
    chmod 0400 $TARGETDIR/client-key.pem
    chmod 0444 $TARGETDIR/client-cert.pem

    mv $TARGETDIR/client-key.pem $TARGETDIR/client-$NAME-key.pem
    mv $TARGETDIR/client-cert.pem $TARGETDIR/client-$NAME-cert.pem
}


if [[ -z $MODE || ($MODE != "ca" && -z $NAME) || -z $PASSWORD || -z $TARGETDIR ]]; then
    usage
fi

mkdir -p $TARGETDIR

if [[ $MODE = "ca" ]]; then
    createCA
elif [[ $MODE = "server" ]]; then
    createServerCert
elif [[ $MODE = "client" ]]; then
    createClientCert
elif [[ $MODE = "tls" ]]; then
    createTLSCert
else
    usage
fi
