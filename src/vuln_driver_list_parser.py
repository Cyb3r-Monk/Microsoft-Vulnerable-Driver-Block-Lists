import base64
import re
import pandas as pd
from io import StringIO

def extract_filehash(friendly_name):
    if not isinstance(friendly_name, str):
        return ""
    # Try to extract after last backslash, else use last word before 'Hash'
    if "\\" in friendly_name:
        candidate = friendly_name.split("\\")[-1].split(" ")[0]
    else:
        # Split by space and look for a 40 or 64 char string
        words = friendly_name.split()
        candidate = ""
        for word in words:
            if len(word) in [40, 64] and all(c in "0123456789abcdefABCDEF" for c in word):
                candidate = word
                break
    # Validate length for SHA1/SHA256
    if len(candidate) in [40, 64]:
        return candidate.upper()
    return ""


def extract_filename(friendly_name):
    if isinstance(friendly_name, str):
        match = re.search(r'([^\s\\]+\.sys)', friendly_name, re.IGNORECASE)
        if match:
            return match.group(1)
    # If there's a backslash, extract before it and add .sys
    if "\\" in friendly_name:
        before_backslash = friendly_name.rsplit("\\", 1)[0]
        # Get last word (after last space)
        last_word = before_backslash.split()[-1] if before_backslash.split() else ""
        if last_word:
            return last_word + ".sys"
    return ""


def hex_to_b64_hash(hex_hash):
    try:
        hash_bytes = bytes.fromhex(hex_hash)
        return base64.b64encode(hash_bytes).decode()
    except Exception as e:
        print(f"Error converting hash: {e}")
        return ""

# Example usage:
# print(hex_to_b64_hash("af7ee8751716dbe151ea8fc6705849174b8324d18c4830e2abbfb98b42f2b42e"))

with open("VulnerableDriverBlockList/SiPolicy_Enforced.xml", "r", encoding="utf-8") as f:
    xml_string = f.read()

df = pd.read_xml(
    StringIO(xml_string),
    xpath="SiPolicy:FileRules/",
    namespaces={"SiPolicy": "urn:schemas-microsoft-com:sipolicy"},
    parser="etree"
)


df.fillna("", inplace=True)
df.to_csv("msft_vuln_driver_block_list.csv", index=False)
df.to_json("msft_vuln_driver_block_list.json", orient="records", indent=2)