#!/bin/bash

echo "Triggering Node.js App endpoints (Port 3000)..."
echo "GET /"
curl -s http://localhost:3000/
echo -e "\n"

echo "GET /math"
curl -s http://localhost:3000/math
echo -e "\n"

echo "GET /time"
curl -s http://localhost:3000/time
echo -e "\n"

echo "GET /id"
curl -s http://localhost:3000/id
echo -e "\n"


echo "Triggering Python App endpoints (Port 8080)..."
echo "GET /"
curl -s http://localhost:8080/
echo -e "\n"

echo "GET /test-libs"
curl -s http://localhost:8080/test-libs
echo -e "\n"

echo "Requests completed."
