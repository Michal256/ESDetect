FROM composer:2 AS build
WORKDIR /app
COPY composer.json .
RUN composer install

FROM php:8.3-cli
WORKDIR /app
COPY --from=build /app/vendor ./vendor
COPY index.php .
CMD ["php", "index.php"]
