#!/bin/bash
echo "Building Java App..."
docker build -t java-app java-app

echo "Building PHP App..."
docker build -t php-app php-app

echo "Building Ruby App..."
docker build -t ruby-app ruby-app

echo "Building Go App..."
docker build -t go-app go-app

echo "Building Rust App..."
docker build -t rust-app rust-app

echo "Building .NET App..."
docker build -t dotnet-app dotnet-app

echo "Building Dart App..."
docker build -t dart-app dart-app

echo "Building Elixir App..."
docker build -t elixir-app elixir-app

echo "Building Swift App..."
docker build -t swift-app swift-app

echo "Building Node.js App..."
docker build -t nodejs-app nodejs-app

echo "Building Python App..."
docker build -t python-app python-app

echo "Building C++ App..."
docker build -t cpp-app cpp-binary

echo "All images built successfully!"
