FROM nginx:1.27-alpine

# /health para el CI y el healthcheck del docker-compose; el resto sirve la interfaz
COPY default.conf /etc/nginx/conf.d/default.conf
COPY src /usr/share/nginx/html
COPY mocks /usr/share/nginx/html/mocks

EXPOSE 80
