#!/bin/bash

echo "Stopping and removing all example containers..."

containers=(
    "java-app"
    "php-app"
    "ruby-app"
    "go-app"
    "rust-app"
    "dotnet-app"
    "elixir-app"
    "swift-app"
    "cpp-app"
    "nodejs-app"
    "python-app"
)

for container in "${containers[@]}"; do
    if docker ps -a -q -f name="^/${container}$" | grep -q .; then
        echo "Stopping $container..."
        docker stop "$container"
        docker rm "$container"
    else
        echo "$container is not running."
    fi
done

echo "All containers stopped."
