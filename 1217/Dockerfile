FROM eclipse-temurin:17-jdk-jammy

WORKDIR /app
COPY piggybank-0.0.1-SNAPSHOT.jar /app/piggybank-0.0.1-SNAPSHOT.jar
RUN apt-get update && \
    apt-get install -y redis-server
ENV ADMIN_PASSWORD=admin_password1!
EXPOSE 8080
CMD service redis-server start && java -jar piggybank-0.0.1-SNAPSHOT.jar
