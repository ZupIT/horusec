banditVersion=$(docker run --rm horus/bandit:latest bandit --version | grep bandit | awk -F " " '{print $2}')
brakemanVersion=$(docker run --rm horus/brakeman:latest brakeman --version | awk -F " " '{print $2}')
enryVersion=$(docker run --rm horus/enry:latest enry --version)
gitAuthorsVersion=$(docker run --rm horus/gitauthors:latest git --version | awk -F " " '{print $3}')
gosecVersion=$(curl -s https://api.github.com/repos/securego/gosec/releases/latest | grep "tag_name" | awk -F '"' '{print $4}')
npmAuditVersion=$(docker run --rm horus/npmaudit:latest npm audit --version)
yarnAuditVersion=$(docker run --rm horus/yarnaudit:latest yarn audit --version )
safetyVersion=$(docker run --rm horus/safety:latest safety --version | awk -F " " '{print $3}')
gitleaksVersion=$(docker run --rm horus/gitleaks:latest gitleaks --version)
spotbugsVersion=$(docker run --rm horus/spotbugs:latest cat /opt/spotbugs/version)

docker tag "horus/bandit:latest" "horus/bandit:$banditVersion"
docker tag "horus/brakeman:latest" "horus/brakeman:$brakemanVersion"
docker tag "horus/enry:latest" "horus/enry:$enryVersion"
docker tag "horus/gitauthors:latest" "horus/gitauthors:$gitAuthorsVersion"
docker tag "horus/gosec:latest" "horus/gosec:$gosecVersion"
docker tag "horus/npmaudit:latest" "horus/npmaudit:$npmAuditVersion"
docker tag "horus/yarnaudit:latest" "horus/yarnaudit:$yarnAuditVersion"
docker tag "horus/safety:latest" "horus/safety:$safetyVersion"
docker tag "horus/gitleaks:latest" "horus/gitleaks:$gitleaksVersion"
docker tag "horus/spotbugs:latest" "horus/spotbugs:$spotbugsVersion"

docker push "horus/bandit:latest" && docker push "horus/bandit:$banditVersion"
docker push "horus/brakeman:latest" && docker push "horus/brakeman:$brakemanVersion"
docker push "horus/enry:latest" && docker push "horus/enry:$enryVersion"
docker push "horus/gitauthors:latest" && docker push "horus/gitauthors:$gitAuthorsVersion"
docker push "horus/gosec:latest" && docker push "horus/gosec:$gosecVersion"
docker push "horus/npmaudit:latest" && docker push "horus/npmaudit:$npmAuditVersion"
docker push "horus/yarnaudit:latest" && docker push "horus/yarnaudit:$yarnAuditVersion"
docker push "horus/safety:latest" && docker push "horus/safety:$safetyVersion"
docker push "horus/gitleaks:latest" && docker push "horus/gitleaks:$gitleaksVersion"
docker push "horus/spotbugs:latest" && docker push "horus/spotbugs:$spotbugsVersion"
