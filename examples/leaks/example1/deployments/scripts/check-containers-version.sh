banditVersion=$(docker run --rm horus/bandit:latest bandit --version | grep bandit | awk -F " " '{print $2}')
brakemanVersion=$(docker run --rm horus/brakeman:latest brakeman --version | awk -F " " '{print $2}')
enryVersion=$(docker run --rm horus/enry:latest enry --version)
gitAuthorsVersion=$(docker run --rm horus/gitauthors:latest git --version | awk -F " " '{print $3}')
gosecVersion=$(docker run --rm horus/gosec:latest gosec --version | grep Version | awk -F " " '{print $2}')
npmAuditVersion=$(docker run --rm horus/npmaudit:latest npm audit --version)
yarnAuditVersion=$(docker run --rm horus/yarnaudit:latest yarn audit --version )
safetyVersion=$(docker run --rm horus/safety:latest safety --version | awk -F " " '{print $3}')
gitleaksVersion=$(docker run --rm horus/gitleaks:latest gitleaks --version)
spotbugsVersion=$(docker run --rm horus/spotbugs:latest cat /opt/spotbugs/version)

echo "bandit: $banditVersion"
echo "brakeman: $brakemanVersion"
echo "enry: $enryVersion"
echo "gitauthors: $gitAuthorsVersion"
echo "gosecVersion: $gosecVersion"
echo "npmauditVersion: $npmAuditVersion"
echo "yarnauditVersion: $yarnAuditVersion"
echo "safetyVersion: $safetyVersion"
echo "gitleaksVersion: $gitleaksVersion"
echo "spotbugsVersion: $spotbugsVersion"