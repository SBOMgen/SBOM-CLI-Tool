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


    print()
    print(r"░██████╗██████╗░░█████╗░███╗░░░███╗")
    print(r"██╔════╝██╔══██╗██╔══██╗████╗░████║")
    print(r"╚█████╗░██████╦╝██║░░██║██╔████╔██║")
    print(r"░╚═══██╗██╔══██╗██║░░██║██║╚██╔╝██║")
    print(r"██████╔╝██████╦╝╚█████╔╝██║░╚═╝░██║")
    print(r"╚═════╝░╚═════╝░░╚════╝░╚═╝░░░░░╚═╝")
    print()
    # print()
    # print(r"   _____ ____   ____  __  __ ")
    # print(r"  / ____|  _ \ / __ \|  \/  |")
    # print(r" | (___ | |_) | |  | | \  / |")
    # print(r"  \___ \|  _ <| |  | | |\/| |")
    # print(r"  ____) | |_) | |__| | |  | |")
    # print(r" |_____/|____/ \____/|_|  |_|")
    # print()


    print("🚀 Let's get started! 🚀")
    print("Please enter the path to your project directory below.\n")

    user_input_path = input("📁 Project Path: ")
    if os.path.isabs(user_input_path):
        project_path = user_input_path
    else:
        project_path = os.path.join(os.getcwd(), user_input_path)
    user_input_format = input("📄 Output Format (xml/json): ")
    if user_input_format not in ['xml', 'json'] or user_input_format == 'json':
        if user_input_format not in ['xml','json']: print('Invalid output format\n\nGenerating in json')
        output_file = 'json'
    elif user_input_format=='xml':
            output_file = 'xml'
    else:
        output_file = 'json'
    return project_path, output_file