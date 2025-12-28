#!/bin/bash

# Ensure output directory exists
mkdir -p sboms

echo "Generating SBOMs for all example images..."

# List of images to scan
images=(
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

for image in "${images[@]}"; do
    echo "Scanning $image..."
    trivy image --format cyclonedx --output "sboms/${image}.json" "$image:latest"
done

echo "SBOM generation complete. Files are in the 'sboms' directory."
