import json
import os
import sys

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from external_targets.real_world_api.app import app

def export_spec():
    spec = app.openapi()
    target_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "openapi.json")
    with open(target_path, "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2)
    print(f"Exported OpenAPI spec to: {target_path}")

if __name__ == "__main__":
    export_spec()
