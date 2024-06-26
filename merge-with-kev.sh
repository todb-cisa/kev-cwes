#!/bin/bash

curl "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | jq > known_exploited_vulnerabilities.json

# Load the known_exploited_vulnerabilities.json and kev-cwe-map.json files
kev_file="known_exploited_vulnerabilities.json"
cwe_file="kev-cwe-map.json"
output_file="updated_known_exploited_vulnerabilities.json"

# Create a temporary file to store the intermediate result
temp_file=$(mktemp)

# Read kev-cwe-map.json into a variable, filtering out "CWE-none" entries
cwe_map=$(jq 'map(select(.cwe_array != ["CWE-none"]) | {(.cve_id): .cwe_array}) | add' "$cwe_file")

# Process known_exploited_vulnerabilities.json and add the CWEs
jq --argjson cwe_map "$cwe_map" '
    .vulnerabilities |= map(
        . + {cwes: ($cwe_map[.cveID] // .cwes)}
    )
' "$kev_file" > "$temp_file"

# Move the temporary file to the output file
mv "$temp_file" "$output_file"

echo "Updated vulnerabilities saved to $output_file"

