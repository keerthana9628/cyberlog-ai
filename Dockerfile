# Builds the Spring Boot backend and bundles the frontend, for Render (free tier).
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY backend/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY backend/src ./src
RUN mvn -q -B -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /build/target/cyberlog-backend-1.0.0.jar app.jar
COPY frontend ./frontend
ENV FRONTEND_DIR=/app/frontend/
ENV DB_PATH=/tmp/cyberlog.db
# Keep memory low so it fits the free 512 MB plan
CMD ["java", "-Xmx300m", "-XX:+UseSerialGC", "-jar", "app.jar"]
