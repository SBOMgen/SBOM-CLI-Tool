import json, os
from json.decoder import JSONDecodeError
from Utility.helpers import replace_placeholders

def swiftParser(path, sbom):
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".resolved") or file.endswith(".json"):
                with open(file_path, "r", encoding="utf-8") as json_file:
                    try:
                        data = json.load(json_file)
                        data = replace_placeholders(data)

                        if "object" in data and "pins" in data["object"]:
                            for pin in data["object"]["pins"]:
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
                                sbom["components"].append(component)
                                dependency = {
                                    "group": "",
                                    "name": package,
                                    "version": version,
                                    "purl": f"pkg:swift/{package.lower()}@{version}",
                                }
                                sbom["dependencies"].append(dependency)
                    except JSONDecodeError as e:
                        print(f"Error decoding JSON in file {file_path}: {e}")
                        print(f"Skipping file: {file_path}")
                        # Skip the file and continue with the next one
                        continue
