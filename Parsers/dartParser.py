import glob
import os, yaml

def dartParser(path, sbom):
    for p in glob.glob(os.path.join(path, "**", "pubspec.lock"), recursive=True):
        with open(p, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
            packages = data.get("packages", [])
            for name, package in packages.items():
                version = package.get("version", "")
                purl = f"pkg:pub/{name}@{version}"
                bomref = purl
                sbom["components"].append(
                    {
                        "group": "",
                        "name": name,
                        "version": version,
                        "scope": "required",
                        "purl": purl,
                        "type": "library",
                        "bom-ref": bomref,
                        "evidence": {
                            "identity": {
                                "field": "purl",
                                "confidence": 1,
                                "methods": [
                                    {
                                        "technique": "manifest-analysis",
                                        "confidence": 1,
                                        "value": p,
                                    }
                                ],
                            }
                        },
                        "properties": [{"name": "SrcFile", "value": p}],
                    }
                )
