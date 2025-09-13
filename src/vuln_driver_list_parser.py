import pandas as pd
from io import StringIO

with open("../VulnerableDriverBlockList/SiPolicy_Enforced.xml", "r", encoding="utf-8") as f:
    xml_string = f.read()

df = pd.read_xml(
    StringIO(xml_string),
    xpath="SiPolicy:FileRules/",
    namespaces={"SiPolicy": "urn:schemas-microsoft-com:sipolicy"},
    parser="etree"
)


df.fillna("", inplace=True)
df.to_csv("../msft_vuln_driver_block_list.csv", index=False)