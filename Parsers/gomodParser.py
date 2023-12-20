import os
import glob
import re

def goModParser(path,sbom):
    for p in glob.glob(os.path.join(path,"**","go.mod"), recursive=True):
        dependencies = {}
        with open(p,"r") as file:
            content = file.read()
            inside_require = False
            for line in content.splitlines():
                line = line.strip()
                GOversion = re.search(r"go\s+(.*)", content)
                if GOversion:
                    GOversion = GOversion.group(1)
                else:
                    GOversion = None
                if line == "require (":
                    inside_require = True
                    continue
                elif line == ")":
                    if inside_require:
                        insider_require = False
                elif inside_require:
                    match = re.match(r"(.*)\s(.*)", line)
                    if match:
                        name, version = match.groups()
                        if version == "indirect":
                            version= name.split()[1]
                            name = name.split()[0]
                        purl = f"pkg:golang/{name}@{version}"
                        bomref = purl
                        sbom["components"].append(
                            {
                                "group": "",
                                "name": name,
                                "version": version,
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
                                "properties": [
                                    {
                                        "name": "SrcFile",
                                        "value": p,
                                    },
                                    {
                                        "name": "GoModVersion",
                                        "value": GOversion,
                                    }
                                ],

                            }
                        )
                        dependencies[bomref] =[]
        for dependency in dependencies:
            sbom["dependencies"].append(
                {
                    "ref": dependency,
                    "dependsOn": dependencies[dependency],
                }
            ) 