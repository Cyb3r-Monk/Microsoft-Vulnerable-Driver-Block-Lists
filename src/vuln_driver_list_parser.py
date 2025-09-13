import pandas as pd

df = pd.read_xml(
    "../VulnerableDriverBlockList/SiPolicy_Enforced.xml",
    xpath="SiPolicy:FileRules/",
    namespaces={"SiPolicy": "urn:schemas-microsoft-com:sipolicy"},
    parser="etree"
)

df.fillna("", inplace=True)
df.to_csv("../msft_vuln_driver_block_list.csv", index=False)