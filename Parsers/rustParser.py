import glob
import os, toml
import  re
def rustParser(path, sbom):
    dependencies_dict = {}
    dependencies_vers = {}
    for p in glob.glob(os.path.join(path, "**", "Cargo.lock"), recursive=True):
        with open(p, "r", encoding="utf-8") as file:
            data = toml.load(file)
            packages = data.get("package", [])
            cargoVersion = data.get("version", "") != ""
            for package in packages:
                name = package.get("name", "")
                version = package.get("version", "")
                purl = f"pkg:rust/{name}@{version}"
                bomref = purl
                if cargoVersion:
                    dependencies_vers[name] = version
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
                dependencies = []
                dependencies_list = package.get("dependencies", [])
                for dep_line in dependencies_list:
                    if cargoVersion:
                        dependencies.append(
                            f"pkg:rust/{dep_line}@{dependencies_vers.get(dep_line, '1.0.0')}"
                        )
                    else:
                        dependency_pattern = re.compile(r"([^\s]+)\s([\d.]+)\s.*")
                        match = dependency_pattern.match(dep_line)
                        if match:
                            name, ver = match.groups()
                            dependency_string = f"pkg:rust/{name}@{ver}"
                            dependencies.append(dependency_string)

                dependencies_dict[bomref] = dependencies
    for i in dependencies_dict:
        dependenciesref = []
        if dependencies_dict[i] == []:
            sbom["dependencies"].append({"ref": i, "dependsOn": []})
        else:
            for k in dependencies_dict[i]:
                for j in sbom["components"]:
                    if j["bom-ref"].find(k) != -1:
                        dependenciesref.append(j["bom-ref"])
            sbom["dependencies"].append({"ref": i, "dependsOn": dependenciesref})
