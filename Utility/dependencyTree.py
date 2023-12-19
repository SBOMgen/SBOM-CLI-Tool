import os

def DependencyTree(sbom, path):
    dependencies = sbom['dependencies']
    if(os.path.exists(path)):
        print("Dependency tree stored at : " + path)
    else:
        print("invalid path")
        return
    with open(os.path.join(path, "depTree.txt"), "w", encoding="utf-8") as file:
        for dependency in dependencies:
            file.write(f"├── {dependency['ref']}\n")
            for sub in dependency["dependsOn"]:
                file.write(f"│   ├── {sub}\n")
            file.write("\n")