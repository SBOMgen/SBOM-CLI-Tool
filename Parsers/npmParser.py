import glob
import json, os

def npmParser(path, sbom):
    for p in glob.glob(os.path.join(path, "**", "package-lock.json"), recursive=True):
        with open(p, "r", encoding="utf-8") as file:
            data = json.load(file)
            dependencies = {}
            for i in data["packages"]:
                if i != "":
                    name = i.split("/").pop()
                    group = (
                        i.split("/")[len(i.split("/")) - 2]
                        if i.split("/")[len(i.split("/")) - 2][0] == "@"
                        else ""
                    )
                    version = data["packages"][i]["version"]
                    try:
                        if data["pacakages"][i]["hasInstallScript"] == True:
                            scope = "required"
                    except:
                        scope = "optional"
                    if group == "":
                        purl = f"pkg:npm/{name}@{version}"
                        bomref = purl
                    else:
                        purl = f"pkg:npm/%40{group[1:]}%2F{name}@{version}"
                        bomref = f"pkg:npm/{group}/{name}@{version}"
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
                    try:
                        cdependencies = []
                        for j in data["packages"][i]["dependencies"]:
                            cdependencies.append(j)
                        dependencies[bomref] = cdependencies
                    except:
                        dependencies[bomref] = []
            for i in dependencies:
                dependenciesref = []
                if dependencies[i] == []:
                    sbom["dependencies"].append({"ref": i, "dependsOn": []})
                else:
                    for k in dependencies[i]:
                        for j in sbom["components"]:
                            if j["bom-ref"].find(k) != -1:
                                dependenciesref.append(j["bom-ref"])
                    sbom["dependencies"].append(
                        {"ref": i, "dependsOn": dependenciesref}
                    )
            file.close()
