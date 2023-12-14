import glob
import os
import xml.etree.ElementTree as ET


def mavenParser(path, sbom):
    projectName = os.path.split(path)[-1]
    namespaces = {"mvn": "http://maven.apache.org/POM/4.0.0"}

    for p in glob.glob(os.path.join(path, "**", "pom.xml"), recursive=True):
        project_tree = ET.parse(p)
        project_root = project_tree.getroot()

        groupId = project_root.find("mvn:groupId", namespaces).text
        artifactId = project_root.find("mvn:artifactId", namespaces).text
        version = project_root.find("mvn:version", namespaces).text
        tree = ET.parse(p)
        root = tree.getroot()

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
                }
            )
            sbom["dependencies"].append({"ref": purl, "dependsOn": []})

