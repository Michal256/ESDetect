# Dynamic Filtering Configuration

ESDetect supports a powerful dynamic filtering system that allows you to define rules to ignore specific events based on their properties. This is useful for reducing noise by filtering out system processes, health checks, or irrelevant file accesses.

## Usage

To apply filters, create a JSON configuration file and pass it to the tool using the `-filter-config` flag:

```bash
sudo ./bpf-detect -filter-config filters.json
```

## Configuration Structure

The configuration file is a JSON array of **Filter Rules**. Each rule contains a description and a list of **Conditions**.

**Logic:**
-   **Rules are OR-ed**: If an event matches *any* of the defined rules, it is filtered out (ignored).
-   **Conditions are AND-ed**: Within a single rule, an event must match *all* conditions to be considered a match.

### JSON Schema

```json
[
  {
    "description": "Description of what this rule filters",
    "conditions": [
      {
        "field": "field_name",
        "operator": "operator_name",
        "value": "value_to_match"
      }
    ]
  }
]
```

## Available Fields

You can filter based on standard event properties or resolved metadata.

| Field | Type | Description |
| :--- | :--- | :--- |
| `type` | string | The type of the process source. Values: `host`, `docker`, `k8s`, `unknown`. |
| `pid` | int | The Process ID. |
| `comm` | string | The command name (e.g., `node`, `java`, `ls`). |
| `filepath` | string | The file path being accessed or executed. |
| `cgroup_paths` | list | The list of cgroup paths associated with the process. |
| `namespace` | string | (K8s only) The Kubernetes namespace. |
| `pod_name` | string | (K8s only) The Kubernetes pod name. |
| `image` | string | The container image name. |
| `container_id` | string | The container ID. |
| `container_name`| string | (Docker only) The container name. |

> **Note:** You can also use any other key present in the resolved metadata `info` map.

## Available Operators

| Operator | Description | Value Type |
| :--- | :--- | :--- |
| `equals` | Exact match. | string, int |
| `not_equals` | Inverse of equals. | string, int |
| `prefix` | String starts with value. | string, list of strings |
| `not_prefix` | String does not start with value. | string, list of strings |
| `suffix` | String ends with value. | string, list of strings |
| `not_suffix` | String does not end with value. | string, list of strings |
| `contains` | String contains the substring. | string, list of strings |
| `not_contains` | String does not contain the substring. | string, list of strings |
| `in` | Field value is present in the provided list. | list of strings |
| `not_in` | Field value is NOT present in the provided list. | list of strings |

> **List Behavior:** For operators like `prefix`, `suffix`, and `contains`, if you provide a list of strings as the `value`, the condition is true if the field matches *any* of the strings in the list.

## Tests

### 1. Filter System Namespaces
Ignore all events coming from Kubernetes system namespaces.

```json
[
  {
    "description": "Ignore K8s System Namespaces",
    "conditions": [
      {
        "field": "namespace",
        "operator": "in",
        "value": ["kube-system", "monitoring", "logging"]
      }
    ]
  }
]
```

### 2. Filter Specific File Types
Ignore access to log files and temporary files.

```json
[
  {
    "description": "Ignore Log and Tmp Files",
    "conditions": [
      {
        "field": "filepath",
        "operator": "suffix",
        "value": [".log", ".tmp", ".swp"]
      }
    ]
  }
]
```

### 3. Filter Health Checks
Ignore `curl` or `wget` commands running against `localhost`.

```json
[
  {
    "description": "Ignore Health Checks",
    "conditions": [
      {
        "field": "comm",
        "operator": "in",
        "value": ["curl", "wget"]
      },
      {
        "field": "type",
        "operator": "equals",
        "value": "k8s"
      }
    ]
  }
]
```

### 4. Filter Host Noise
Ignore common noisy paths on the host, but keep container events.

```json
[
  {
    "description": "Ignore Host System Paths",
    "conditions": [
      {
        "field": "type",
        "operator": "equals",
        "value": "host"
      },
      {
        "field": "filepath",
        "operator": "prefix",
        "value": ["/proc/", "/sys/", "/dev/"]
      }
    ]
  }
]
```
