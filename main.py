# Program Name; File Analysis and Detection Tool
# Program Description: File Analysis and Detection Tool is designed for analyzing binary files to determine their type and identify potential suspicious characteristics. It performs a multi-step analysis of the file using Yara rules and the pefile library to gain insights into the file's nature and potential security risks
# Written By: Vanessa Rice
# Written On: September 20, 2023

#imports
import yara
import pefile


# Step 2: Use Yara rules to determine the file type
def match_yara(file_path, rule_path):
    try:
        rule = yara.compile(rule_path)
        matches = rule.match(filepath=file_path)
        if matches:
            return matches[0].rule
        else:
            return "Unknown"
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    file_path = "part4.file"
    rule_path = "part4.yara"

    result = match_yara(file_path, rule_path)
    print(f"File Type: {result}")


    match_yara("part4.file", "part4.yara")


# Step 3: Check for imports and record the number of DLLs and functions
def get_imports(path):
    try:
        pe = pefile.PE(path)
        pe.parse_data_directories()
        total_functions = 0
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            total_functions += len(entry.imports)

        # Print the results as comments
        print(f"File: {path}")
        print(f"Number of imported DLLs: {len(pe.DIRECTORY_ENTRY_IMPORT)}")
        print(f"Total number of imported functions: {total_functions}")

    except Exception as e:
        print(f"[!] Error: {e}")


# Step 4: Analyze the sections of the file and record their permissions
def analyze_sections(path):
    try:
        pe = pefile.PE(path)
        print(f"File: {path}")

        # Iterate through the sections and print their names and permissions
        for section in pe.sections:
            section_name = section.Name.decode().rstrip("\x00")
            flags = get_flags(section)
            print(f"Section: {section_name} | Permissions: {flags}")

    except Exception as e:
        print(f"[!] Error: {e}")


def get_flags(section):
    flags = ""
    if section.Characteristics & 0x40000000:
        flags += "R"
    if section.Characteristics & 0x80000000:
        flags += "W"
    if section.Characteristics & 0x20000000:
        flags += "X"
    return flags


file_path = "part4.file"
analyze_sections(file_path)

# Step 5: Identify three suspicious things about the file
print("\nSuspicious Things:")
print("1. The file type is not what was expected.")
print("2. The number of imported DLLs and functions is unusually high.")
print("3. The file may have executable sections (X permissions).")
