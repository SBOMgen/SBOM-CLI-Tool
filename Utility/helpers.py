import os

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

# === utility function for cli ===
def get_project_path():
    print("\n🌟 Welcome to the SBOM Generator! 🌟")
    print("Let's create a Software Bill of Materials (SBOM) for your project.\n")

    print("  _____ _____   _____            ______  _____  ")
    print(" |  __ \  __ \ / ____|   /\     |  ____|/ ____| ")
    print(" | |__) | |__) | (___    /  \    | |__  | (___   ")
    print(" |  _  /|  _  / \___ \  / /\ \   |  __|  \___ \  ")
    print(" | | \ \| | \ \ ____) |/ ____ \  | |____ ____) | ")
    print(" |_|  \_\_|  \_\_____/ /_/    \_\ |______|_____/  \n")


    print("🚀 Let's get started! 🚀")
    print("Please enter the path to your project directory below.\n")

    user_input_path = input("📁 Project Path: ")
    if os.path.isabs(user_input_path):
        project_path = user_input_path
    else:
        project_path = os.path.join(os.getcwd(), user_input_path)

    return project_path