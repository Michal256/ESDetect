FROM dart:stable AS build
WORKDIR /app
COPY pubspec.* ./
RUN dart pub get
COPY . .
RUN dart compile exe main.dart -o main

FROM scratch
COPY --from=build /runtime/ /
COPY --from=build /app/main /app/bin/
CMD ["/app/bin/main"]
