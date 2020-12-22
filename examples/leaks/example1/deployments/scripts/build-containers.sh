
docker build deployments/dockerfiles/bandit/ -t horus/bandit:latest
docker build deployments/dockerfiles/brakeman/ -t horus/brakeman:latest
docker build deployments/dockerfiles/enry/ -t horus/enry:latest
docker build deployments/dockerfiles/gitauthors/ -t horus/gitauthors:latest
docker build deployments/dockerfiles/gosec/ -t horus/gosec:latest
docker build deployments/dockerfiles/npmaudit/ -t horus/npmaudit:latest
docker build deployments/dockerfiles/npmaudit/ -t horus/yarnaudit:latest
docker build deployments/dockerfiles/safety/ -t horus/safety:latest
docker build deployments/dockerfiles/gitleaks/ -t horus/gitleaks:latest
docker build deployments/dockerfiles/spotbugs/ -t horus/spotbugs:latest