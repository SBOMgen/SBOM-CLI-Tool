import os;
import zipfile;

def zip_extract(zipPath):
    with zipfile.ZipFile(zipPath) as z:
        z.extractall(os.path.dirname(zipPath))
        return os.path.join(os.path.dirname(zipPath), os.path.splitext(os.path.basename(zipPath))[0])
# path = "C:\\Users\\divya\\Downloads\\maven\\maven-modular.zip"
# print(os.path.dirname("C:\\Users\\divya\\Downloads\\wsa_pacman-main.zip"))
# output_path=os.path.dirname(path)
# print(os.path.join(os.path.dirname(path),'sbom.xml'))
# print(os.path.split(path)[-1].split('.')[-1])