FROM eclipse-temurin:25-jdk

WORKDIR /app

COPY src ./src
COPY web ./web

RUN mkdir -p out && javac -d out src/*.java

EXPOSE 8080

CMD ["java", "-cp", "out", "Main"]
