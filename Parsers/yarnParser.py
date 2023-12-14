import glob
import os
import re

def YarnParser(path, sbom):
    paths = glob.glob(os.path.join(path, "**", "yarn.lock"), recursive=True)
    ignoreList = ["node_modules"]
    for p in paths:
        f = 0
        for i in ignoreList:
            if i in p:
                f = 1
                break
        if f == 1:
            continue
        with open(p, "r", encoding="utf-8") as file:
            dependencies = {}
            for line in file:
                match = re.match("^(.+)@(.+)$", line.strip())
                if match:
                    mgroups = match.groups()
                    name = (
                        mgroups[0]
                        .split(",")[-1]
                        .strip()
                        .split("/")[-1]
                        .replace('"', "")
                    )
                    group = (
                        mgroups[0].split(",")[-1].strip().split("/")[0].replace('"', "")
                        if (len(mgroups[0].split(",")[-1].strip().split("/")) > 1)
                        else ""
                    )
                    version = (
                        file.readline()
                        .strip()
                        .split(" ")[-1]
                        .replace('"', "")
                        .replace("~", "")
                        .replace("^", "")
                    )
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
                    f = 0
                    dependencies[bomref] = []
                    nline = file.readline().strip()
                    while True:
                        if nline == "dependencies:":
                            f = 1
                            break
                        elif nline == "":
                            break
                        elif not nline:
                            break
                        nline = file.readline().strip()
                    if f == 1:
                        nline = file.readline().strip()
                        while True:
                            if (not nline) or nline == "":
                                break
                            dependencies[bomref].append(nline.split(" ")[0].strip())
                            nline = file.readline().strip()
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
