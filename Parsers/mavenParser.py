import glob
import os
import xml.etree.ElementTree as ET


def mavenParser(path, sbom):
    projectName = os.path.split(path)[-1]
    namespaces = {"mvn": "http://maven.apache.org/POM/4.0.0"}

    for p in glob.glob(os.path.join(path, "**", "pom.xml"), recursive=True):
        project_tree = ET.parse(p)
        project_root = project_tree.getroot()

        tree = ET.parse(p)
        root = tree.getroot()
        groupId = root.find("mvn:groupId", namespaces).text
        artifactId = root.find("mvn:artifactId", namespaces).text
        version = root.find("mvn:version", namespaces).text
        purl = f"pkg:maven/{groupId}/{artifactId}@{version}"
        if "components" not in sbom["metadata"]["component"]:
            sbom["metadata"]["component"]["components"] = []
        sbom["metadata"]["component"]["components"].append(
            {
                "group": groupId,
                "name": artifactId,
                "version": version,
                "purl": purl,
                "type": "library",
                "bom-ref": purl,
                "properties": [
                    {"name": "buildFile", "value": p},
                    {"name": "projectDir", "value": os.path.split(p)[0]},
                    {"name": "rootDir", "value": path},
                ],
            })
        for dependency in root.findall(".//mvn:dependency", namespaces):
            groupId = dependency.find("mvn:groupId", namespaces).text
            artifactId = dependency.find("mvn:artifactId", namespaces).text
            version = dependency.find("mvn:version", namespaces).text
            scope = dependency.find("mvn:scope", namespaces)
            scope = (
                scope.text if scope is not None else "compile"
            )
            purl = f"pkg:maven/{groupId}/{artifactId}@{version}"
            sbom["components"].append(
                {
                    "type": "library",
                    "bom-ref": purl,
                    "name": artifactId,
                    "version": version,
                    "group": groupId,
                    "purl": purl,
                    "scope": scope,
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
            sbom["dependencies"].append({"ref": purl, "dependsOn": []})

