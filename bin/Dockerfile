FROM eclipse-temurin:23.0.1_11-jre-alpine

WORKDIR /app

COPY ./target/06_Forum-Service-MongoDB-0.0.1-SNAPSHOT.jar ./forum-service.jar

ENTRYPOINT ["java","-jar","/app/forum-service.jar"]
