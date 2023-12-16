import json, os
import datetime
import argparse

from Parsers.conanParser import conanParser
from Parsers.dartParser import dartParser
from Parsers.dotnetParser import dotnetParser
from Parsers.gradleGroovyParser import gradleGroovyParser
from Parsers.gradlekotlinDSLParser import gradlekotlinDSLParser
from Parsers.mavenParser import mavenParser
from Parsers.npmParser import npmParser
from Parsers.phpParser import phpParser
from Parsers.rustParser import rustParser
from Parsers.swiftParser import swiftParser
from Parsers.yarnParser import YarnParser
from Parsers.rubyParser import rubyparser
from Parsers.requirementsParser import requirementsParser
from Parsers.gomodParser import goModParser
from Utility.helpers import get_project_path


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
    requirementsParser(path, sbom)
    conanParser(path, sbom)
    dartParser(path, sbom)
    dotnetParser(path, sbom)
    gradleGroovyParser(path, sbom)
    gradlekotlinDSLParser(path, sbom)
    mavenParser(path, sbom)
    rustParser(path, sbom)
    swiftParser(path, sbom)
    rubyparser(path,sbom)
    goModParser(path,sbom)

    with open(os.path.join(path, "sbom.json"), "w", encoding="utf-8") as file:
        json.dump(sbom, file, indent=4)
        file.close()
    return sbom


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate Software Bill of Materials (SBOM) for a project.')
    parser.add_argument('project_path', metavar='project_path', type=str, nargs='?', help='Path to the project directory')
    
    args = parser.parse_args()
    if args.project_path:
        user_input_path = args.project_path
        if not os.path.isabs(user_input_path):
            user_input_path = os.path.join(os.getcwd(), user_input_path)

        project_path = user_input_path
    else:
        project_path = get_project_path()
    print("\n🚀 Generating SBOM...")
    project_path = os.path.abspath(project_path)
    createsbom(project_path)
    print(f"\n✅ SBOM generated successfully!")
    print(f"📄 SBOM file is located at: {os.path.join(project_path, 'sbom.json')}")
