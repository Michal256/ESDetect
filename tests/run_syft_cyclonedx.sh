#!/bin/bash

# Directory to store SBOMs
OUTPUT_DIR="sboms-cyclonedx"
mkdir -p "$OUTPUT_DIR"

# List of images to scan (matching build_all.sh)
IMAGES=(
    "java-app"
    "php-app"
    "ruby-app"
    "go-app"
    "rust-app"
    "dotnet-app"
    "elixir-app"
    "swift-app"
    "nodejs-app"
    "python-app"
    "cpp-app"
)

# Check if syft is installed
if command -v syft &> /dev/null; then
    SYFT_CMD="syft"
elif [ -f "./bin/syft" ]; then
    SYFT_CMD="./bin/syft"
elif [ -f "../bin/syft" ]; then
    SYFT_CMD="../bin/syft"
else
    echo "Error: 'syft' not found. Please install it or run ./test.sh to install locally."
    exit 1
fi

echo "Using Syft: $SYFT_CMD"

for img in "${IMAGES[@]}"; do
    echo "Generating CycloneDX SBOM for $img..."
    # Generate SBOM in CycloneDX JSON format
    # Explicitly specify 'docker:' source to ensure we scan the image, not the local directory
    $SYFT_CMD "docker:${img}:latest" -o cyclonedx-json > "$OUTPUT_DIR/$img.json"
    
    if [ $? -eq 0 ]; then
        echo "  -> Saved to $OUTPUT_DIR/$img.json"
    else
        echo "  -> Failed to generate SBOM for $img"
    fi
done

echo "Done!"
