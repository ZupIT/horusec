# Instalação com Helm

### Nota de casos de uso
O caso de uso que foi testado com esses Helm Charts envolve um namespace limpo dentro de um cluster Kubernetes,
e todos os comandos devem ser modificados de acordo para que usem o mesmo namespace.

### Notas quanto ao MongoDB e ao RabbitMQ
Devido a incompatibilidade de versões e APIs, optamos por agora em manter o banco de dados MongoDB dentro do cluster
e também o serviço de mensageria utilizado pelas aplicações, o RabbitMQ. Para tal, nós utilizamos os Helms públicos
para ambos. Segue o comando:

 - `helm install horusec-mongodb --set auth.username=[INSIRA AQUI O USUÁRIO DO BANCO],auth.password=[INSIRA AQUI A SENHA DO BANCO],auth.database=horusec_db bitnami/mongodb` *

 - `helm install horusec-mq-rabbitmq bitnami/rabbitmq`

\* É importante salvar essas configurações de usuário e senha pois elas serão necessárias para a criação dos secrets que são obrigatórios para as aplicações funcionarem.

### Preparação do ambiente
Para o uso do Horusec em um ambiente de nuvem gerenciada é necessário a criação dos seguinte recursos:
  - Banco de dados Amazon RDS com a API do PostgresSQL na versão 12.3 Internamente nós usamos um banco de dados com as seguintes configurações:
      - Nome: db.m5.xlarge
      - Memória: 16 GB
      - vCPUs: 4
      - Armazenamento: 20 GB à 1 TB, 100% SSD (dentro do Amazon EBS)

  - Um cluster Kubernetes no Amazon EKS, na versão 1.17. Internamente usamos um cluster com 3 nós, com as seguintes configurações para cada nó:
    - Nome: t3.large
    - Memória: 8 GB
    - vCPUs: 2
    - Armazenamento (de cada nó): 30 GB, 100% SSD (dentro do Amazon EBS)

### Criação dos Secrets
Para a execução dos Helms, é necessário que já estejam criados dentro do namespace os secrets com as configurações descritas a seguir.
Todos os secrets seguem esse formato:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: [Nome do secret]
  namespace: [Namespace]
type: Opaque
data:
  [Nome do secret]: [Valor em base64]
```

Seguindo esse formato, os secrets que o Horusec utiliza são os seguintes:

 - Nome do Secret: jwt-token. Coloque aqui o salt para a criação dos tokens JWT.
 - Nome do Secret: broker-username. Coloque aqui o username para a aplicaçao acessar o RabbitMQ.
 - Nome do Secret: broker-password. Coloque aqui a senha para a aplicaçao acessar o RabbitMQ.
 - Nome do Secret: database-uri. Coloque aqui a URI para acessar o PostgreSQL.
 - Nome do Secret: database-username. Coloque aqui o usuário do banco para utilizar na autenticação.
 - Nome do Secret: database-password. Coloque aqui a senha do banco para utilizar na autentiação

## Preparação dentro do cluster
Para que os Pods sejam configurados corretamente, você precisará criar os seguintes componentes dentro do cluster antes de aplicar qualquer Helm
 - Secrets:
    - Para o pod horusec-account:
       - Nome da variabel de ambiente: HORUSEC_JWT_SECRET_KEY                     Coloque aqui o valor do secret: jwt-token
       - Nome da variabel de ambiente: HORUSEC_DATABASE_SQL_URI                   Coloque aqui o valor do secret: database-uri
       - Nome da variavel de ambiente: HORUSEC_BROKER_USERNAME                    Coloque aqui o valor do secret: broker-username
       - Nome da variabel de ambiente: HORUSEC_BROKER_PASSWORD                    Coloque aqui o valor do secret: broker-password

     - Para o pod horusec-analytic:
       - Nome da variabel de ambiente: HORUSEC_JWT_SECRET_KEY                     Coloque aqui o valor do secret: jwt-token
       - Nome da variabel de ambiente: HORUSEC_DATABASE_SQL_URI                   Coloque aqui o valor do secret: database-uri
       - Nome da variabel de ambiente: HORUSEC_BROKER_USERNAME                    Coloque aqui o valor do secret: broker-username
       - Nome da variabel de ambiente: HORUSEC_BROKER_PASSWORD                    Coloque aqui o valor do secret: broker-password
     
     - Para o pod horusec-api:
       - Nome da variabel de ambiente: HORUSEC_BROKER_USERNAME                    Coloque aqui o valor do secret: broker-username
       - Nome da variabel de ambiente: HORUSEC_BROKER_PASSWORD                    Coloque aqui o valor do secret: broker-password
       - Nome da variabel de ambiente: HORUSEC_DATABASE_USERNAME                  Coloque aqui o valor do secret: database-username
       - Nome da variabel de ambiente: HORUSEC_DATABASE_PASSWORD                  Coloque aqui o valor do secret: database-password
       - Nome da variabel de ambiente: HORUSEC_DATABASE_SQL_URI                   Coloque aqui o valor do secret: database-uri
       - Nome da variabel de ambiente: HORUSEC_JWT_SECRET_KEY                     Coloque aqui o valor do secret: jwt-token


## Webapp
Por se tratar de SPA totalmente estático optamos por hospeda-lo em um bucket S3. Para fazer deploy do mesmo é necessário ter 
disponível as URLs que compoem o Horusec.

- HORUSEC_ACCOUNT_URL
- HORUSEC_API_URL
- HORUSEC_ANALYTIC_URL

### Criação do bucket
Após criação do bucket com a devida policy para hospedar site estático será necessário atualizar as 
URLs dos serviços e sincronizar os arquivos com o bucket.

Sugestão de policy (pública):
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::{bucket_name}/*"
            ]
        }
    ]
}
```

- 1. Atualizar URLs dos servições

horusec-manager/dist/index.html
```html
<script>
    window.__horusec_account_url = "horusec account url comes here"
    window.__horusec_api_url = "horusec api url comes here"
    window.__horusec_analytic_ur = "horusec analytic url comes here"
</script>
```

- 2. Sincronizar arquivos com bucket (Utilizando AWS CLI)

```bash
cd horusec-manager/dist && aws s3 sync . s3://{buecket_name}
```

# Configurando pipeline

Imagem: 671982376808.dkr.ecr.us-east-1.amazonaws.com/horusec-cli:{version}
Comand: /bin/horusec-cli start -A ${HORUSEC_TOKEN} -d ${PROJECT} -u ${HORUSEC_API_URL}


## CLI

### Usage

```bash
Horusec CLI prepares packages to be analyzed by the Horusec Analysis API

Usage:
  horusec-cli [command]

Available Commands:
  help        Help about any command
  start       Start horusec-cli

Flags:
  -h, --help   help for horusec-cli

Use "horusec-cli [command] --help" for more information about a command.
```

### Start command

```bash
Start the Horusec analysis in the current path

Usage:
  horusec-cli start [flags]

Examples:
horusec start

Flags:
  -a, --analysis-timeout int      The timeout threshold for the Horusec CLI wait for the analysis to complete. (default 600)
  -A, --authorization string      The authorization token for the Horusec API
  -h, --help                      help for start
  -u, --horusec-url string          The Horusec API address to access the analysis engine (default "http://0.0.0.0:8000")
  -i, --ignore string             Paths to ignore in the analysis
  -s, --ignore-severity string    The level of vulnerabilities to ignore in the output
  -O, --json-output-file string   The file to write the output JSON
  -r, --monitor-retry-count int   The number of retries for the monitor. (default 15)
  -o, --output-format string      The format for the output to be shown. Options are: text (stdout) and json (default "text")
  -t, --request-timeout int       The timeout threshold for the request to the Horusec API (default 300)
```

