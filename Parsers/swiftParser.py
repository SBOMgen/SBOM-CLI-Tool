import os
import datetime
import json
import xml.etree.ElementTree as ET
from json.decoder import JSONDecodeError

def replace_placeholders(data):
    if isinstance(data, dict):
        for key, value in data.items():
            data[key] = replace_placeholders(value)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            data[i] = replace_placeholders(item)
    elif isinstance(data, str):
        data = data.replace("{{", "").replace("}}", "").replace("$", "dummy_")
    return data

def process_pin(pin):
        package = pin["package"]
        version = pin["state"]["version"]
        repositoryURL = pin["repositoryURL"]

        component = {
            "group": "",
            "name": package,
            "version": version,
            "purl": f"pkg:swift/{package.lower()}@{version}",
            "type": "library",
            "bom-ref": f"pkg:swift/{package.lower()}@{version}",
            "repositoryURL": repositoryURL,
        }
        dependency = {
            "group": "",
            "name": package,
            "version": version,
            "purl": f"pkg:swift/{package.lower()}@{version}",
            "dependsOn": []
        }

        # Add sub-dependencies
        sub_dependencies = pin.get("dependencies", {}).get("dependencies", [])
        for sub_dep in sub_dependencies:
            sub_package = sub_dep.get("package", "")
            sub_version = sub_dep.get("state", {}).get("version", "")
            sub_dependency_ref = f"pkg:swift/{sub_package.lower()}@{sub_version}"
            dependency["dependsOn"].append(sub_dependency_ref)

        return component, dependency

def swiftParser(path, sbom):
    projectName = os.path.split(path)[-1]
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".resolved"):
                with open(file_path, 'r', encoding='utf-8') as json_file:
                    try:
                        data = json.load(json_file)
                        data = replace_placeholders(data)

                        if "object" in data and "pins" in data["object"]:
                            for pin in data["object"]["pins"]:
                                component, dependency = process_pin(pin)
                                sbom["components"].append(component)
                                sbom["dependencies"].append(dependency)

                    except JSONDecodeError as e:
                        # print(f"Error decoding JSON in file {file_path}: {e}")
                        # print(f"Skipping file: {file_path}")
                        continue

    # with open(os.path.join(path, 'sbom.json'), 'w', encoding='utf-8') as file1:
    #     json.dump(sbom, file1, indent=4)
    # print(sbom)
    return sbom
