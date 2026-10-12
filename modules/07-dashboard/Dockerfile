# Usa un servidor web ligero
FROM nginx:alpine

# Copiar el código fuente y los mocks
COPY ./src /usr/share/nginx/html
COPY ./mocks /usr/share/nginx/html/mocks

# Copiar configuración de Nginx (si tienes un default.conf, si no, puedes omitir esta línea)
# COPY ./default.conf /etc/nginx/conf.d/default.conf

EXPOSE 80