FROM golang:1.23 AS build
WORKDIR /app
COPY go.mod .
# COPY go.sum . # Skipping go.sum for simplicity in generation, usually required
COPY main.go .
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o myapp

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/myapp .
CMD ["./myapp"]
