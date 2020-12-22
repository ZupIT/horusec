printf "Generating Local Token      ..." && sleep 60

token=$(curl -s -H "Content-Type: application/json" -H "Authorization: Basic aHVza3lDSVVzZXI6aHVza3lDSVBhc3N3b3Jk" http://localhost:8888/api/1.0/token -X POST -d '{"repositoryURL": "https://github.com/ZupIT/horus.git"}' | awk -F '"' '{print $4}')

if [ $? -eq 0 ]; then
    echo " done"
else
    echo " error. Try running make generate-local-token"
fi

echo "export HORUS_CLIENT_TOKEN=\"$token\"" >> .env
