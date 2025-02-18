import os
import re  # For pattern-based matching

def identify_vendor(config_file_path):
    """
    Identify the vendor of the given configuration file.

    Parameters:
    - config_file_path: Path to the configuration file.

    Returns:
    - Vendor name as a string.
    """
    # Refined patterns for higher precision
    vendor_patterns = {
        "Cisco": [r"^interface\s", r"ip route", r"access-list", r"line vty", r"crypto ikev2"],
        "Fortinet": [r"^config\s", r"^edit\s", r"^next$", r"^set\s", r"^end$"],
        "Palo Alto": [r"<config>", r"<devices>", r"<entry>", r"set deviceconfig", r"<phash>"]
    }

    if not os.path.isfile(config_file_path):
        return f"Error: The path '{config_file_path}' is not a valid file."

    try:
        print(f"Attempting to read file: {config_file_path}")
        with open(config_file_path, "r") as file:
            config_content = file.readlines()
            print("File successfully read. Analyzing content...\n")

        # Match patterns line by line for higher accuracy
        for line in config_content:
            for vendor, patterns in vendor_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):  # Use regex for precise matching
                        print(f"Matched pattern '{pattern}' for vendor '{vendor}'.")
                        return f"The configuration belongs to the vendor: {vendor}"

        print("No matching patterns found.")
        return "Vendor could not be identified. Please ensure the file contains recognizable patterns."

    except FileNotFoundError:
        return f"Error: File not found at {config_file_path}"

    except Exception as e:
        return f"Error: {str(e)}"


# Example usage
if __name__ == "__main__":
    try:
        config_path = input("Enter the path to the configuration file: ").strip()
        if not config_path:
            print("Error: No file path provided.")
        else:
            result = identify_vendor(config_path)
            print(result)
    except Exception as main_error:
        print(f"Unhandled error: {main_error}")
