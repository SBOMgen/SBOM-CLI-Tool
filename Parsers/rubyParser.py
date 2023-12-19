import os
import re
import glob
global_dict =[]
def global_dict_list(content):
    current_gem = None
    for line in content.split('\n'):
        match_gem = re.match(r'\s{4}([\w-]+) \(([\d.]+)\)\s*$', line)
        if match_gem:
           current_gem = match_gem.group(1)
           component3={
                "name": current_gem,
                "version": match_gem.group(2)
            }
           global_dict.append(component3)
             


def parse_gemfile_lock(content, sbom, lock_file_path):
    global_dict_list(content)
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
                "purl": f"pkg:gem/{current_gem}@{match_gem.group(2)}",
                "bom-ref": f"pkg:gem/{current_gem}@{match_gem.group(2)}",
                "dependsOn":[],
                "evidence": {
       "identity": {
           "field": "purl",
           "confidence": 1,
           "methods": [
               {
                   "technique": "manifest-analysis",
                   "confidence": 1,
                   "value": os.path.abspath(lock_file_path)
               }
           ]
       }
          },
                "properties":{
                    "name": "SrcFile",
           "value": os.path.abspath(lock_file_path)
                }
            }
            component2={
                "bom-ref": f"pkg:gem/{current_gem}@{match_gem.group(2)}",
                "dependsOn":[],
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
                component["dependsOn"] = current_dependencies
               
                dict=[]
                for i in component["dependsOn"]:
                     
                     
                     for j in global_dict:
                         if(j["name"] == i["name"]):
                             i["version"] = j["version"]
                     k= "pkg:gem/"+i["name"]+"@"+i["version"]        
                     dict.append(k)
                component2["dependsOn"] =dict    

                if component["bom-ref"] not in added_dependencies:

                    sbom["dependencies"].append(component2)
                    added_dependencies.add(component["bom-ref"])

    


    
    

def rubyparser(path, sbom):
   for p in glob.glob(os.path.join(path, "**", 'Gemfile.lock'), recursive=True):
       with open(p, 'r') as lock_file:
           gemfile_lock_content = lock_file.read()

       sbom = parse_gemfile_lock(gemfile_lock_content, sbom, p)

   

