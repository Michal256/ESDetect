FROM ubuntu:24.04
RUN apt-get update && apt-get install -y g++
RUN mkdir /app
COPY ./src/test.cpp /app/test.cpp
RUN g++ /app/test.cpp -o /app/test
RUN chmod +x /app/test
CMD ["/app/test"]

