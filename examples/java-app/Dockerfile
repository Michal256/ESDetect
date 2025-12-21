FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /app/target/my-app-1.0-SNAPSHOT.jar /app/app.jar
CMD ["java", "-jar", "app.jar"]
