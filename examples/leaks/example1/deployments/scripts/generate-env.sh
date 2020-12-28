# horus client default environment variables
HORUS_CLIENT_REPO_URL="https://github.com/ZupIT/horus.git"
HORUS_CLIENT_REPO_BRANCH="poc-golang-gosec"
HORUS_CLIENT_API_ADDR="http://localhost:8888"
HORUS_CLIENT_API_USE_HTTPS="false"

# Adding default envs vars to run be used by make run-client
echo "export HORUS_CLIENT_REPO_URL=\"$HORUS_CLIENT_REPO_URL\"" > .env
echo "export HORUS_CLIENT_REPO_BRANCH=\"$HORUS_CLIENT_REPO_BRANCH\"" >> .env
echo "export HORUS_CLIENT_API_ADDR=\"$HORUS_CLIENT_API_ADDR\"" >> .env
echo "export HORUS_CLIENT_API_USE_HTTPS=\"$HORUS_CLIENT_API_USE_HTTPS\"" >> .env
