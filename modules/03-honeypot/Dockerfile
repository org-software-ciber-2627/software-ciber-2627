# Parte 1: Descarga de librerias y compilación de la web
FROM maven:3.9-eclipse-temurin-25 AS build

RUN groupadd --system http \
    && useradd --system --gid http --home-dir /home/http http \
    && mkdir /workspace \
    && mkdir /home/http \
    && chown -R http:http /workspace /home/http

WORKDIR /workspace

COPY --chown=http:http pom.xml ./pom.xml
COPY --chown=http:http src ./src

USER http

RUN mvn package -DskipTests

# Parte 2: Ejecucion de la web
FROM eclipse-temurin:25-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system http \
    && useradd --system --gid http --home-dir /home/http http \
    && mkdir -p /http/data \
    && mkdir /home/http \
    && chown -R http:http /http /home/http

WORKDIR /http

COPY --from=build --chown=http:http /workspace/target/*.jar /http/main.jar

USER http

ENV SERVER_PORT=80

ENTRYPOINT ["java", "-jar", "/http/main.jar"]
