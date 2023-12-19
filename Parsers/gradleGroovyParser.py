import glob
import os
import re


def gradleGroovyParser(path, sbom):
    paths = glob.glob(os.path.join(path, "**", "build.gradle"), recursive=True)
    
    for p in paths:
        dependencies = {}
        with open(p, "r") as file:
            content = file.read()
            name = os.path.split(os.path.dirname(p))[-1]

            group_match = re.search(r"group '(.*)'", content)
            grp = group_match.group(1) if group_match else ""

            version_match = re.search(r"version '(.*)'", content)
            ver = version_match.group(1) if version_match else ""

            source_match = re.search(r"sourceCompatibility = (.*)", content)
            src = source_match.group(1) if source_match else ""

            purl = f"pkg:maven/{grp}/{name}@{ver}"
            bomref = purl
            if "components" not in sbom["metadata"]["component"]:
                sbom["metadata"]["component"]["components"] = []
            sbom["metadata"]["component"]["components"].append(
                {
                    "group": grp,
                    "name": name,
                    "version": ver,
                    "purl": purl,
                    "type": "library",
                    "bom-ref": bomref,
                    "properties": [
                        {"name": "buildFile", "value": p},
                        {"name": "projectDir", "value": os.path.split(p)[0]},
                        {"name": "rootDir", "value": path},
                    ],
                }
            )
        with open(p, "r") as file:
            inside_dependencies = False
            for line in file:
                line = line.strip()
                if line == "dependencies {":
                    inside_dependencies = True
                    continue
                elif line == "}":
                    if inside_dependencies:
                        break
                elif inside_dependencies:
                    match = re.match(r"(\w+)\(\"(.+):(.+):(.+)\"\)", line)
                    if match:
                        scope, group, name, version = match.groups()

                        purl = f"pkg:maven/{group}/{name}@{version}"
                        bomref = purl

                        sbom["components"].append(
                            {
                                "group": group,
                                "name": name,
                                "version": version,
                                "scope": "required"
                                if scope in ["implementation", "api"]
                                else "optional"
                                if scope
                                in [
                                    "compileOnly",
                                    "runtimeOnly",
                                    "testImplementation",
                                    "testCompileOnly",
                                    "testRuntimeOnly",
                                ]
                                else "unknown",
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
                                        "name": "GradleProfleName", 
                                        "value": p,
                                        # "complieClasspath"
                                        # if scope in ["implementation", "api"]
                                        # else "testCompileClasspath"
                                        # if scope
                                        # in [
                                        #     "testImplementation",
                                        #     "testCompileOnly",
                                        #     "testRuntimeOnly",
                                        # ]
                                        # else "runtimeClasspath"
                                        # if scope in ["runtimeOnly"]
                                        # else "compileOnlyClasspath"
                                        # if scope in ["compileOnly"]
                                        # else "unknown",
                                    }
                                ],
                            }
                        )
                    dependencies[bomref] = []

        for ref, dep in dependencies.items():
            sbom["dependencies"].append({"ref": ref, "dependsOn": dep})
