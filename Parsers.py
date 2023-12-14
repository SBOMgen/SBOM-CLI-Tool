import glob
import json, os, yaml, toml
import datetime, re
import xml.etree.ElementTree as ET
from json.decoder import JSONDecodeError


def phpParser(path, sbom):
    for p in glob.glob(os.path.join(path, "**", "composer.lock"), recursive=True):
        with open(p, "r", encoding="utf-8") as file:
            data = json.load(file)
            dependencies = {}
            packages = data["packages"] + data["packages-dev"]
            for i in packages:
                if len(i["name"].split("/")) == 2:
                    name = i["name"].split("/")[0]
                    group = i["name"].split("/")[1]
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
                    purl = f"pkg:composer/%40{group[1:]}%2F{name}@{version}"
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


def conanParser(path, sbom):
    component_data = {}
    for conanfile_path in glob.glob(
        os.path.join(path, "**", "conanfile.txt"), recursive=True
    ):
        with open(conanfile_path, "r", encoding="utf-8") as file:
            f = False
            for line in file:
                if line.startswith("\n") or line.startswith("[generators]"):
                    parts = line
                    f = False
                if f:
                    package_name, package_version = line.split("/")
                    component_data[package_name] = package_version
                if line.startswith("[requires]"):
                    parts = line
                    f = True

        for package_name, package_version in component_data.items():
            purl = f"pkg:conan/{package_name}@{package_version}"
            bom_ref = purl

            component = {
                "group": "",
                "name": package_name,
                "version": package_version,
                "scope": "required",
                "purl": purl,
                "type": "library",
                "bom-ref": bom_ref,
                "evidence": {
                    "identity": {
                        "field": "purl",
                        "confidence": 1,
                        "methods": [
                            {
                                "technique": "manifest-analysis",
                                "confidence": 1,
                                "value": conanfile_path,
                            }
                        ],
                    }
                },
                "properties": [{"name": "SrcFile", "value": conanfile_path}],
            }

            sbom["components"].append(component)
    for component in sbom["components"]:
        dependencies_ref = [
            dep["bom-ref"]
            for dep in sbom["components"]
            if dep["name"] in component_data
        ]
        sbom["dependencies"].append(
            {"ref": component["bom-ref"], "dependsOn": dependencies_ref}
        )


def dartParser(path, sbom):
    for p in glob.glob(os.path.join(path, "**", "pubspec.lock"), recursive=True):
        with open(p, "r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
            packages = data.get("packages", [])
            for name, package in packages.items():
                version = package.get("version", "")
                purl = f"pkg:dart/{name}@{version}"
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


def dotnetParser(path, sbom):
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".csproj"):
                tree = ET.parse(file)
                root = tree.getroot()
                item_group = root.find("ItemGroup")
                if item_group is not None:
                    for item in item_group:
                        if item.tag == "PackageReference":
                            component = {
                                "group": "",
                                "name": item.get("Include"),
                                "version": item.get("Version"),
                                "purl": f"pkg:nuget/{item.get('Include')}@{item.get('Version')}",
                                "type": "library",
                                "bom-ref": f"pkg:nuget/{item.get('Include')}@{item.get('Version')}",
                            }
                            sbom["components"].append(component)


def gradleGroovyParser(path, sbom):
    paths = glob.glob(os.path.join(path, "**", "build.gradle"), recursive=True)

    for p in paths:
        dependencies = {}
        with open(p, "r") as file:
            content = file.read()

            name = os.path.split(os.path.dirname(p))[-1]

            group_match = re.search(r"group = '(.*)'", content)
            grp = group_match.group(1) if group_match else ""

            version_match = re.search(r"version = '(.*)'", content)
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
                                "properties": [
                                    {
                                        "name": "GradleProfleName", 
                                        "value": "complieClasspath"
                                        if scope in ["implementation", "api"]
                                        else "testCompileClasspath"
                                        if scope
                                        in [
                                            "testImplementation",
                                            "testCompileOnly",
                                            "testRuntimeOnly",
                                        ]
                                        else "runtimeClasspath"
                                        if scope in ["runtimeOnly"]
                                        else "compileOnlyClasspath"
                                        if scope in ["compileOnly"]
                                        else "unknown",
                                    }
                                ],
                            }
                        )
                    dependencies[bomref] = []

        for ref, dep in dependencies.items():
            sbom["dependencies"].append({"ref": ref, "dependsOn": dep})


def gradlekotlinDSLParser(path, sbom):
    paths = glob.glob(os.path.join(path, "**", "build.gradle.kts"), recursive=True)

    for p in paths:
        dependencies = {}
        with open(p, "r") as file:
            content = file.read()

            name = os.path.split(os.path.dirname(p))[-1]

            group_match = re.search(r"group = \"(.*)\"", content)
            grp = group_match.group(1) if group_match else ""

            version_match = re.search(r"version = \"(.*)\"", content)
            ver = version_match.group(1) if version_match else ""

            source_match = re.search(r"sourceCompatibility = (.*)", content)
            src = source_match.group(1) if source_match else ""

            purl = f"pkg:maven/{grp}/{name}@{ver}"
            if "components" not in sbom["metadata"]["component"]:
                sbom["metadata"]["component"]["components"] = []
            bomref = purl
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
                        component = {
                            "group": group,
                            "name": name,
                            "version": version,
                            "purl": purl,
                            "type": "library",
                            "bom-ref": bomref,
                        }
                        value = (
                            "api"
                            if scope in ["implementation", "api", "kapt"]
                            else "testCompileClasspath"
                            if scope
                            in [
                                "testImplementation",
                                "testCompileOnly",
                                "testRuntimeOnly",
                            ]
                            else "runtimeClasspath"
                            if scope in ["runtimeOnly"]
                            else "compileOnlyClasspath"
                            if scope in ["compileOnly"]
                            else "unknown"
                        )
                        scope = (
                            "required"
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
                            else scope
                        )
                        if scope != "classpath":
                            component["scope"] = scope
                            component["properties"] = [
                                {"name": "GradleProfileName", "value": value}
                            ]

                        sbom["components"].append(component)
                    dependencies[bomref] = []

        for ref, dep in dependencies.items():
            sbom["dependencies"].append({"ref": ref, "dependsOn": dep})


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


# === utility function for swift ===
def replace_placeholders(data):
    if isinstance(data, dict):
        for key, value in data.items():
            data[key] = replace_placeholders(value)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            data[i] = replace_placeholders(item)
    elif isinstance(data, str):
        data = data.replace("{{", "").replace("}}", "").replace("$", "dummy_")
    return data


def swiftParser(path, sbom):
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".resolved") or file.endswith(".json"):
                with open(file_path, "r", encoding="utf-8") as json_file:
                    try:
                        data = json.load(json_file)
                        data = replace_placeholders(data)

                        if "object" in data and "pins" in data["object"]:
                            for pin in data["object"]["pins"]:
                                package = pin["package"]
                                version = pin["state"]["version"]
                                repositoryURL = pin["repositoryURL"]

                                component = {
                                    "group": "",
                                    "name": package,
                                    "version": version,
                                    "purl": f"pkg:swift/{package.lower()}@{version}",
                                    "type": "library",
                                    "bom-ref": f"pkg:swift/{package.lower()}@{version}",
                                    "repositoryURL": repositoryURL,
                                }
                                sbom["components"].append(component)
                                dependency = {
                                    "group": "",
                                    "name": package,
                                    "version": version,
                                    "purl": f"pkg:swift/{package.lower()}@{version}",
                                }
                                sbom["dependencies"].append(dependency)
                    except JSONDecodeError as e:
                        print(f"Error decoding JSON in file {file_path}: {e}")
                        print(f"Skipping file: {file_path}")
                        # Skip the file and continue with the next one
                        continue

#ruby
import os
import re
import json
import datetime

def parse_gemfile_lock(content, sbom):
    current_gem = None
    current_dependencies = None
    added_dependencies = set()

    for line in content.split('\n'):
        match_gem = re.match(r'\s{4}([\w-]+) \(([\d.]+)\)\s*$', line)
        match_dep = re.match(r'\s{6}([\w-]+) \((.*)\)\s*$', line)

        if match_gem:
            current_gem = match_gem.group(1)
            component = {
                "group": "",
                "name": current_gem,
                "version": match_gem.group(2),
                "type": "library",
                "bom-ref": f"pkg:ruby/{current_gem}@{match_gem.group(2)}"
            }
            sbom["components"].append(component)
            current_dependencies = []

        if match_dep:
            dep_name = match_dep.group(1)
            dep_version = match_dep.group(2)
            dependency = {
                "group": "dependencies",
                "type": "library",
                "name": dep_name,
                "version": dep_version,
            }
            current_dependencies.append(dependency)

        if current_dependencies and line.startswith(' ' * 8):
            dep_name, dep_version = map(str.strip, line.split(' ', 1))
            dependency = {
                "group": "dependencies",
                "type": "library",
                "name": dep_name,
                "version": dep_version,
            }
            current_dependencies.append(dependency)

        if current_dependencies and line.strip().endswith(')'):
            if current_dependencies:
                component["dependOns"] = current_dependencies
                if component["bom-ref"] not in added_dependencies:
                    sbom["dependencies"].append(component)
                    added_dependencies.add(component["bom-ref"])

    return sbom

def rubyparser(path, sbom):
    with open(os.path.join(path, 'Gemfile.lock'), 'r') as lock_file:
        gemfile_lock_content = lock_file.read()
    
    sbom = parse_gemfile_lock(gemfile_lock_content, sbom)
    
    return sbom
def createsbom(path):
    projname = os.path.split(path)[-1]
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": "1",
        "metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "component": {
                "group": "",
                "name": projname,
                "version": "0.0.0",
                "type": "application",
                "bom-ref": f"pkg:npm/{projname}@0.0.0",
            },
        },
        "components": [],
        "services": [],
        "dependencies": [],
    }

    phpParser(path, sbom)
    npmParser(path, sbom)
    YarnParser(path, sbom)
    conanParser(path, sbom)
    dartParser(path, sbom)
    dotnetParser(path, sbom)
    gradleGroovyParser(path, sbom)
    gradlekotlinDSLParser(path, sbom)
    mavenParser(path, sbom)
    rustParser(path, sbom)
    swiftParser(path, sbom)
    sbom =rubyparser(path, sbom)

    with open(os.path.join(path, "sbom.json"), "w", encoding="utf-8") as file:
        json.dump(sbom, file, indent=4)
        file.close()
    return sbom


if __name__ == "__main__":

    createsbom("C:\\Users\\divya\\OneDrive\\Pictures\\Desktop\\sih2023\\gradle\\SoskaRikcyAndMorty")

