# expandas - A Python lib for expanding ASNs
Expandas fetches data by the means of loaders, which enables multiple
ways to fetch the data. All the loaders provide the data using the
standard models - ASSet and ASNumber object.

The expandas distribution is delivered with the following loaders;

 - **BGPQ3Loader** - Fetches data from whois servers, using bgpq3 binary
 - **RIPERESTLoader** - Fetches data from the RIPE REST API
 - **RIPEDumpLoader** - Downloads and parses ripe database dumps

### Sample usage
```
import expandas
loader = expandas.loader.RIPERESTLoader()

as_glesys = loader.load_asset("AS-GLESYS")

# Loop through asset members as lists
for member in as_glesys:
    if "8.8.8.8/32" in member:
        print("Found 8.8.8.8 in asn {}".format(member.asn))

    # loop through member prefixes as lists
    for prefix in member:
        print(prefix)

if 2914 in as_glesys:
   # my asset contains as2914
```
