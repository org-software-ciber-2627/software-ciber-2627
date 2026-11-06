FROM nginx:1.27-alpine

# /health para el CI y el healthcheck del docker-compose; el resto sirve la interfaz
COPY default.conf /etc/nginx/conf.d/default.conf
COPY src /usr/share/nginx/html
# Solo se publica el mock que consume la web (SIEM). Los mocks de SOAR y Escáner son servicios
# Flask independientes y su código no debe quedar accesible desde nginx.
COPY mocks/siem-alerts.json /usr/share/nginx/html/mocks/siem-alerts.json

EXPOSE 80
