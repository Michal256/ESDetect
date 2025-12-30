#!/bin/bash
docker run -it --rm \
  --privileged \
  --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug:rw \
  -v /run:/run:ro \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v /var/lib/docker:/var/lib/docker:ro \
  -v $(pwd)/logs:/app/logs \
  michalz256/esdetect:1.0 \
  -output-dir /app/logs \
  -debug=false