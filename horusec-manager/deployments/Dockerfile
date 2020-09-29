FROM node:14.5.0-alpine AS builder

WORKDIR /usr/src/app

COPY ./horusec-manager/ .

RUN ls

RUN npm install
RUN npm run build
RUN npm run lint

FROM nginx:1.18.0-alpine

COPY --from=builder /usr/src/app/dist /var/www
COPY ./horusec-manager/deployments/nginx.conf /etc/nginx/conf.d/default.conf

CMD ["nginx", "-g", "daemon off;"]
