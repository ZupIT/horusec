FROM mongo:4.0.3

ADD deployments/mongo-init.js /docker-entrypoint-initdb.d/