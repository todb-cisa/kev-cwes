#!/bin/zsh

# Collect Data
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev" | jq > kev-cves.json &&

# Filter for CWEs and their sources
jq '[.vulnerabilities[] | {id: .cve.id, weaknesses: .cve.weaknesses}]' kev-cves.json > kev-cwes-nvd.json &&

# Normalize missing CWEs
jq 'map({id, weaknesses: [.weaknesses[] | {source, type, description: [.description[] | if .value == "NVD-CWE-Other" or .value == "NVD-CWE-noinfo" then {lang, value: "CWE-none"} else . end]}]})' kev-cwes-nvd.json > normalized-cwes.json &&

# Drop conflicts
jq 'map({id, weaknesses: (.weaknesses | if length == 1 then . else map(select(.source != "nvd@nist.gov")) end)})' normalized-cwes.json > deconflicted-cwes.json &&

# Pare down the data
jq 'map({id, CWESource: .weaknesses[0].source, CWEs: [.weaknesses[].description[].value]})' deconflicted-cwes.json > just-cwes.json &&

# Rename the fields
jq 'map({cve_id: .id, cwe_source: .CWESource, cwe_array: .CWEs})' just-cwes.json > renamed-fields.json &&

# Copy the final
mv renamed-fields.json kev-cwe-map.json && rm deconflicted-cwes.json normalized-cwes.json just-cwes.json kev-cwes-nvd.json