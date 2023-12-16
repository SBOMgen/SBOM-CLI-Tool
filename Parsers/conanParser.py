import glob
import os


def conanParser(path, sbom):
    component_data = {}
    for conanfile_path in glob.glob(os.path.join(path, "**", "conanfile.txt"), recursive=True):
        with open(conanfile_path, "r", encoding="utf-8") as file:
            f = False
            for line in file:
                if line.startswith("\n") or line.startswith("[generators]"):
                    parts = line
                    f = False
                if f:
                    package_name, package_version = line.strip().split("/")
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
