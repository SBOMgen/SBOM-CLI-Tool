import glob
import json, os

def requirementsParser(path, sbom):
    for p in glob.glob(os.path.join(path, "**", "requirements.txt"), recursive=True):
        if ('env' in p):
            continue
        with open(p, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if (line==""):
                    continue
                if ('#' not in line):
                    sline = line.split('==')
                    group=''
                    name = sline[0]
                    version='latest'
                    if (len(sline) == 2):
                        version=sline[1]
                    purl = f"pkg:pypi/{name}@{version}"
                    bomref = purl
                    scope = 'required'
                    sbom["components"].append(
                        {
                            "group": group,
                            "name": name,
                            "version": version,
                            "scope": scope,
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
            file.close()
