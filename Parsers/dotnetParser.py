import os
import xml.etree.ElementTree as ET

def dotnetParser(path, sbom):
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".csproj"):
                tree = ET.parse(file)
                root = tree.getroot()
                item_group = root.find("ItemGroup")
                if item_group is not None:
                    for item in item_group:
                        if item.tag == "PackageReference":
                            component = {
                                "group": "",
                                "name": item.get("Include"),
                                "version": item.get("Version"),
                                "purl": f"pkg:nuget/{item.get('Include')}@{item.get('Version')}",
                                "type": "library",
                                "bom-ref": f"pkg:nuget/{item.get('Include')}@{item.get('Version')}",
                            }
                            sbom["components"].append(component)
