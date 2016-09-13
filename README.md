# expandas - A Python lib for expanding ASNs

Expandas provides two different loaders, one using the RIPE REST API and one 
executing bgpq3 to load data.

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
