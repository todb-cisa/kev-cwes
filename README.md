# KEV-CWEs

Some tooling to collect CWEs, and their provenance, for KEV items.

# Notes


# Goals

Produce a list of CVEs that are on the KEV, and annotate them with associated CWEs, in this order of preference:

* CNA-supplied CWE
* NVD-supplied CWE
* None or Other CWEs

Note that some CVEs will have CWEs assigned by either, or both, of NVD, and one issuer may have multiple CWEs.
CWE annoations must always be treated as arrays from a single source.

# TODO

* Wrap this all up in a usable script
* Publish it somewhere on the internet
* In the output, sort by date added, then CVE ID (latest first).
* Handle the case when there are three sources. Currently, the only sources observed are NVD and the issuing CNA, but that might change.
  - This will probably only change when NVD becomes a proper ADP, and then other ADPs show up to provide their own CWEs.
  - When that happens, I suspect the JSON format will change anyway, so this will need to be updated for the new version.

# Files

* `kev-cves.json` : The entire NVD list of KEV CVEs, according to NIST.
* `samples-kev-cves.json` : A small set that represents all seen value types for weaknesses.
* `samples-final.json` : The desired output of whatever scripts I write, when applied to `samples-final.json`

# Test data

`samples-kev-cves.json` is a test file that contains data on the following:

    * CVE-2002-0367 is "NVD-CWE-Other" added by nvd@nist.gov. Rewrite this as "CWE-none".
    * CVE-2008-0655 is "NVD-CWE-noinfo" added by nvd@nist.gov. Rewrite this as "CWE-none".
    * CVE-2007-5659 is "CWE-119" added by nvd@nist.gov. Use this as an array of one.
    * CVE-2008-3431 is "CWE-264" added by nvd@nist.gov. Use this as an array of one.
    * CVE-2022-28810 is both "CWE-78" and "CWE-798", both added by nvd@nist.gov. Capture both in an array of two.
    * CVE-2023-27524 is "CWE-1188", added by security@apache.org. There is no CWE added by NVD.
    * CVE-2023-29298 is "CWE-284" added by psirt@adobe.com and "NVD-CWE-Other" added by nvd@nist.gov. Prefer CWE-284.
    * CVE-2023-27992 is "CWE-78" added by nvd@nist.gov and "CWE-78" by security@zyxel.com.tw. Prefer the Zyxel one even when they match.
    * CVE-2023-27997 is "CWE-787" added by nvd@nist.gov and "CWE-122" by psirt@fortinet.com. Prefer the Fortinet one when they conflict.

Because it's JSON, the ordering of elements shouldn't matter. Don't rely on a hueristic of matching the last CWE in a set, in other words.

# Pipeline

Here's the basic pipeline, all using jq. Convert this to a real script someday.

## Collect Data

First off, let's just collect the raw data from NVD:

`curl "https://services.nvd.nist.gov/rest/json/cves/2.0?hasKev" | jq > kev-cves.json`

But we really just need to filter just for the CWEs and their sources:

`jq '[.vulnerabilities[] | {id: .cve.id, weaknesses: .cve.weaknesses}]' kev-cves.json > kev-cwes-nvd.json`

## Normalize missing CWEs

NVD uses NVD-CWE-Other and NVD-CWE-noinfo, but both mean "none" for our purposes.

`jq 'map({id, weaknesses: [.weaknesses[] | {source, type, description: [.description[] | if .value == "NVD-CWE-Other" or .value == "NVD-CWE-noinfo" then {lang, value: "CWE-none"} else . end]}]})' kev-cwes-nvd.json > normalized-cwes.json`

## Drop conflicts

We'll want to prefer the issuing CNA in case of conflicts. Gotta choose one!

`jq 'map({id, weaknesses: (.weaknesses | if length == 1 then . else map(select(.source != "nvd@nist.gov")) end)})' normalized-cwes.json > deconflicted-cwes.json`

## Pare down the data

`jq 'map({id, CWESource: .weaknesses[0].source, CWEs: [.weaknesses[].description[].value]})' deconflicted-cwes.json > just-cwes.json`

## Rename the fields

`jq 'map({cve_id: .id, cwe_source: .CWESource, cwe_array: .CWEs})' just-cwes.json > renamed-fields.json`

## Copy the final

`mv renamed-fields.json kev-cwe-map.json && rm deconflicted-cwes.json normalized-cwes.json just-cwes.json kev-cwes-nvd.json`


