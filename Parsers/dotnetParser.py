import os
import glob
import xml.etree.ElementTree as ET

def dotnetParser(path, sbom):
      for p in glob.glob(os.path.join(path, '**', '*.csproj'), recursive=True):
        with open(p, 'r', encoding='utf-8') as file:
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
                                "evidence": {
                                    "identity": {
                                        "field": "purl",
                                        "confidence": 1,
                                        "methods": [
                                            {
                                                "technique": "manifest-analysis",
                                                "confidence": 1,
                                                "value": os.path.abspath(p)
                                            }
                                        ],
                                    }
                                },
                                "properties": [{"name": "SrcFile", "value": os.path.abspath(p)}],
                            }
                            sbom["components"].append(component)
