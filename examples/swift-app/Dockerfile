FROM swift:5.10
WORKDIR /app
COPY . .
RUN swift build -c release
CMD [".build/release/SwiftApp"]
