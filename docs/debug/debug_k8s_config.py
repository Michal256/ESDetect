
import os
import json
import sys

container_id = "46cbb73a47bb8869a7447f3939f059f9f28de8bf7991ab28de9eeebf1a290fa3"
base_dirs = [
    "/run/containerd/io.containerd.runtime.v2.task/k8s.io",
    "/var/snap/microk8s/common/run/containerd/io.containerd.runtime.v2.task/k8s.io"
]

print(f"Checking for container: {container_id}")

for base_dir in base_dirs:
    path = os.path.join(base_dir, container_id, "config.json")
    print(f"Checking path: {path}")
    if os.path.exists(path):
        print(f"  [OK] File exists.")
        try:
            with open(path, "r") as f:
                data = json.load(f)
                print("  [OK] JSON loaded.")
                annotations = data.get("annotations", {})
                print(f"  Annotations found: {len(annotations)}")
                print(json.dumps(annotations, indent=2))
                
                # Check if there are other places where metadata might be
                print("  Top level keys:", list(data.keys()))
                if 'labels' in data:
                     print("  Labels:", json.dumps(data['labels'], indent=2))
        except Exception as e:
            print(f"  [ERROR] Failed to read/parse: {e}")
    else:
        print(f"  [MISSING] File not found.")
