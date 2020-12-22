docker stop horus_API > /dev/null
docker rm horus_API > /dev/null
cd deployments && docker-compose -f docker-compose.yml up -d --build --no-deps api
if [ $? -ne 0 ]; then
  cd ..
  exit 1;
fi
cd ..
while true; do
    if [ "$(curl -s -k -L localhost:8888/healthcheck)" = "WORKING" ]; then
        echo "horus_API is UP!"
        break
    else
        echo "Waiting healthcheck..."
    fi
    sleep 15
done
