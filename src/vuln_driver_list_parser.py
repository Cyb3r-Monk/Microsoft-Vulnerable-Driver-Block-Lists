import base64
import re
import pandas as pd
from lxml import etree
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
# Update FileName if empty
df["ExtractedFileName"] = df["FriendlyName"].apply(extract_filename)
df.loc[df["FileName"] == "", "FileName"] = df.loc[df["FileName"] == "", "ExtractedFileName"]
df.drop(columns=["ExtractedFileName"], inplace=True)

df["FileHash"] = df["FriendlyName"].apply(extract_filehash)
df["b64FileHash"] = df["FileHash"].apply(hex_to_b64_hash)
df.rename(columns={"Hash": "Authentihash"}, inplace=True)
# Reorder columns
cols = df.columns.tolist()
cols_reorder = ["ID", "FriendlyName", "FileName", "Authentihash", "FileHash", "b64FileHash"]
cols = [col for col in cols_reorder if col in cols] + [col for col in cols if col not in cols_reorder]
df = df[cols]
df.to_csv("msft_vuln_driver_block_list.csv", index=False)
df.to_json("msft_vuln_driver_block_list.json", orient="records", indent=2)

# Process Signers
tree = etree.parse("VulnerableDriverBlockList/SiPolicy_Enforced.xml")
signers = tree.xpath('//ns:Signers/ns:Signer', namespaces={'ns': 'urn:schemas-microsoft-com:sipolicy'})

data = []
for signer in signers:
    row = {
        'ID': signer.get('ID'),
        'Name': signer.get('Name'),
    }
    certroot = signer.find('ns:CertRoot', namespaces={'ns': 'urn:schemas-microsoft-com:sipolicy'})
    if certroot is not None:
        row['CertRootType'] = certroot.get('Type')
        row['CertRootValue'] = certroot.get('Value')
    else:
        row['CertRootType'] = ''
        row['CertRootValue'] = ''
    # data.append(row)
    certpublisher = signer.find('ns:CertPublisher', namespaces={'ns': 'urn:schemas-microsoft-com:sipolicy'})
    if certpublisher is not None:
        row['CertPublisher'] = certpublisher.get('Value')
    else:
        row['CertPublisher'] = ''
    data.append(row)

df = pd.DataFrame(data)
df.fillna("", inplace=True)
df.to_csv("msft_vuln_driver_signers.csv", index=False)
df.to_json("msft_vuln_driver_signers.json", orient="records", indent=2)