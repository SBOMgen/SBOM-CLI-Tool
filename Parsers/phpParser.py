import glob
import json, os


def phpParser(path, sbom):
    for p in glob.glob(os.path.join(path, "**", "composer.lock"), recursive=True):
        with open(p, "r", encoding="utf-8") as file:
            data = json.load(file)
            dependencies = {}
            packages = data["packages"] + data["packages-dev"]
            for i in packages:
                if len(i["name"].split("/")) == 2:
                    name = i["name"].split("/")[1]
                    group = i["name"].split("/")[0]
                else:
                    name = i["name"]
                    group = ""

                version = i["version"]
                version = version.replace("v", "")
                scope = "required"
                if group == "":
                    purl = f"pkg:composer/{name}@{version}"
                    bomref = purl
                else:
                    purl = f"pkg:composer/{group}/{name}@{version}"
                    bomref = f"pkg:composer/{group}/{name}@{version}"
                license = i.get("license", [])
                licenses = []
                source = i.get("source", {})
                if source != {}:
                    source["type"] = "vcs"
                    source.pop("reference")
                for j in license:
                    licenses.append(
                        {
                            "license": {
                                "id": j,
                                "url": f"https://opensource.org/licenses/{j}",
                            }
                        }
                    )
                sbom["components"].append(
                    {
                        "group": group,
                        "name": name,
                        "version": version,
                        "scope": scope,
                        "licenses": licenses,
                        "purl": purl,
                        "externalReferences": [source],
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
                cdependencies = []
                try:
                    for j in i["require"]:
                        cdependencies.append(j)
                except:
                    pass
                try:
                    for j in i["require-dev"]:
                        cdependencies.append(j)
                except:
                    pass
                dependencies[bomref] = cdependencies
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
