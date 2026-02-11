import yara
import os

def run_scanner(folder_path, rules_file):
    # 1. Compile the rules
    try:
        rules = yara.compile(filepath=rules_file)
    except yara.SyntaxError as e:
        print(f"Error in YARA rules: {e}")
        return

    print(f"{'File Name':<30} | {'Identified As / Matches':<30}")
    print("-" * 65)

    # 2. Iterate through the folder
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        
        # Skip directories, only scan files
        if os.path.isfile(file_path):
            try:
                matches = rules.match(file_path)
                
                if matches:
                    # 'matches' is a list of rule names that triggered
                    match_names = ", ".join([m.rule for m in matches])
                    print(f"{filename:<30} | {match_names}")
                else:
                    print(f"{filename:<30} | No matches (Clean/Unknown)")
                    
            except Exception as e:
                print(f"{filename:<30} | Error scanning: {e}")

# Usage
if __name__ == "__main__":
    # Path to your 200 files
    my_folder = "./target_files" 
    my_rules = "my_rules.yar"
    
    run_scanner(my_folder, my_rules)