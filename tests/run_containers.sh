#!/bin/bash

echo "Starting all containers in detached mode..."

echo "Running Java App..."
docker run  -itd --name java-app java-app

echo "Running PHP App..."
docker run  -itd --name php-app php-app

echo "Running Ruby App..."
docker run  -itd --name ruby-app ruby-app

echo "Running Go App..."
docker run  -itd --name go-app go-app

echo "Running Rust App..."
docker run  -itd --name rust-app rust-app

echo "Running .NET App..."
docker run  -itd --name dotnet-app dotnet-app

echo "Running Dart App..."
docker run  -itd --name dart-app dart-app

echo "Running Elixir App..."
docker run  -itd --name elixir-app elixir-app

echo "Running Swift App..."
docker run  -itd --name swift-app swift-app

echo "Running C++ App..."
docker run  -itd --name cpp-app cpp-app

echo "Running Node.js App..."
docker run  -itd --name nodejs-app -p 3000:3000 nodejs-app

echo "Running Python App..."
docker run  -itd --name python-app -p 8080:8080 python-app

echo "All containers started."
