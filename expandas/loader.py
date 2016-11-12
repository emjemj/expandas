from abc import ABCMeta, abstractmethod
from .model import ASSet, ASNumber

class BaseLoader(metaclass=ABCMeta):
    """ Base class for all different loaders """

    @abstractmethod
    def load_asset(self, name):
        pass

    @abstractmethod
    def load_asn(self, asn):
        pass


class BGPQ3Loader(BaseLoader):
    """ Use bgpq3 to fetch data from whois server """

    def __init__(self, bgpq3_path = None):
        self.bgpq3_path = self.findbin(bgpq3_path)

    def findbin(self, supplied_path = None):
        """ Attempt to locate bgpq3 binary """
        import os

        # Use supplied path if present
        if supplied_path:
            return supplied_path

        # Otherwise fallback to $BGPQ3_PATH environment variable
        t_path =  os.environ.get("BGPQ3_PATH", None)
        if t_path is not None and os.path.isfile(t_path) and os.access(t_path, os.X_OK):
            return t_path

        # Last of all check $PATH environment variable
        for path in os.environ.get("PATH").split(os.pathsep):
            t_path = os.path.join(path, "bgpq3")

            if os.path.isfile(t_path) and os.access(t_path, os.X_OK):
               return t_path
        # Give up
        raise Exception("Unable to find bgpq3 binary. Please install in $PATH, set $BGPQ3_PATH or specify in constructor")

    def exec(self, cmd):
        """ Execute bgpq3 command """
        import subprocess
        import json

        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, cwd="/")
        output = p.communicate()
        return json.loads(output[0].decode("UTF-8"))["NN"]

    
    def load_asset(self, name):
        cmd = [ self.bgpq3_path, "-3j", "-f1", name ]
        members = []

        for entry in self.exec(cmd):
            members.append(self.load_asn(entry))

        return ASSet(name, members=members)

    def load_asn(self, asn):
        import ipaddress

        cmd = [ self.bgpq3_path, "-3j", "AS{}".format(asn) ]

        inet = []
        inet6 = []

        for entry in self.exec(cmd + [ "-4" ]):
            i = ipaddress.ip_network(entry["prefix"])
            inet.append(i)

        for entry in self.exec(cmd + [ "-6" ]):
            i = ipaddress.ip_network(entry["prefix"])
            inet6.append(i)

        return ASNumber(asn, inet=inet, inet6=inet6)

class RIPERESTLoader(BaseLoader):
    """ Use RIPE's REST API to load data """

    def load_asset(self, name):
        self.expanded = {}
        self.members = []
        self.expand(name)

        return ASSet(name, members = self.members)

    def load_asn(self, asn):
        import requests
        import ipaddress

        urlparams = {
            "query-string": "AS{}".format(asn),
            "inverse-attribute": "origin"
        }

        r = requests.get("http://rest.db.ripe.net/search.json", params=urlparams)

        if r.status_code == requests.codes.not_found:
            # No entries could be found, return empty lists for now
            return ASNumber(asn, inet=[], inet6=[])

        if r.status_code != requests.codes.ok:
            raise Exception("Something went wrong when expanding AS{}".format(asn))

        inet = []
        inet6 = []

        for obj in r.json()["objects"]["object"]:
            for attr in obj["attributes"]["attribute"]:
                if attr["name"] == "route":
                    inet.append(ipaddress.ip_network(attr["value"]))
                if attr["name"] == "route6":
                    inet6.append(ipaddress.ip_network(attr["value"]))

        return ASNumber(asn, inet=inet, inet6=inet6)

    def expand(self, asset):
        """ Recursively expand as-set """
        for attr in self.get_members(asset):
            if attr["referenced-type"] == "aut-num":
                asn = int(attr["value"].upper().replace("AS", ""))
                self.members.append(self.load_asn(asn))
            else:
                if attr["value"] in self.expanded:
                    # Avoid infinite loop by keeping track of already
                    # expanded entries
                    continue
                self.expanded[attr["value"]] = 1
                self.expand(attr["value"])

    def get_members(self, asset):
        import requests
        url = "http://rest.db.ripe.net/RIPE/AS-SET/{}.json".format(asset)
        headers = { "content-type": "application/json" }
        r = requests.get(url, headers=headers)

        if r.status_code == requests.codes.not_found:
            # Entry doesn't exist in RIPE database, return empty list
            return []

        members = []
        # This could probably do with some error handling
        for attr in r.json()["objects"]["object"][0]["attributes"]["attribute"]:
            if attr["name"] == "members":
                members.append(attr)
        return members

class RIPEDumpLoader(BaseLoader):
    """ Loader that fetches ripe database dumps and expands from that data """
    files = [ "ripe.db.as-set.gz", "ripe.db.route.gz", "ripe.db.route6.gz" ]

    def __init__(self):
        self.inet = {}
        self.inet6 = {}
        self.assets = {}
        self.expanded = {}
        self.load_dumps()
        self.parse_dumps()

    def parse_dumps(self):
        """ decompress and parse database dumps """
        import gzip

        parsers = {
            "ripe.db.as-set.gz": self.asset_parser,
            "ripe.db.route.gz": self.route_parser,
            "ripe.db.route6.gz": self.route6_parser
        }

        for f in self.files:
            fpath = "/tmp/{}".format(f)

            with gzip.open(fpath, "rb") as handle:
                for line in handle.readlines():
                    line = line.strip().decode("ISO-8859-1")
                    if line.find(":") != -1:
                        tpl = line.split(":", 1)
                        parsers[f](tpl[0].strip(), tpl[1].strip())

    def asset_parser(self, key, val):
        """ parse as-set dump """
        import re

        if key == "as-set":
            self.curr = val
            if val not in self.assets:
                self.assets[val.upper()] = []
        elif key == "members":
            if val.find(",") != -1:
                pcs = val.split(",")
                for e in pcs:
                    e = e.strip()
                    if re.match("^AS\d+$", e):
                        self.assets[self.curr.upper()].append({ "data": e, "type": "aut-num" })
                    else:
                        self.assets[self.curr.upper()].append({ "data": e.upper(), "type": "as-set" })
            elif re.match("^AS\d+$", val):
                self.assets[self.curr.upper()].append({ "data": val, "type": "aut-num" })
            else:
                self.assets[self.curr.upper()].append({ "data": val.upper(), "type": "as-set" })

    def route_parser(self, key, val):
        """ parse route dump """
        if key == "route":
            self.curr = val
        elif key == "origin":
            # Some weird people put comments in origin field
            com = val.find("#")
            if com != -1:
                val = val[0:com]
            asn = int(val.upper().replace("AS", ""))
            if asn not in self.inet:
                self.inet[asn] = []

            self.inet[asn].append(self.curr)

    def route6_parser(self, key, val):
        """ parse route6 dump """
        if key == "route6":
            self.curr = val
        elif key == "origin":
             # Some weird people put comments in origin field
            com = val.find("#")
            if com != -1:
                val = val[0:com]
            asn = int(val.upper().replace("AS", ""))
            if asn not in self.inet6:
                self.inet6[asn] = []

            self.inet6[asn].append(self.curr)

    def load_dumps(self):
        """ Download dump files if nonexistant or older than 24 hours """
        import os
        import time

        # Download files if needed
        for f in self.files:
            fpath = "/tmp/{}".format(f)

            if os.path.isfile(fpath):
                st = os.stat(fpath)

                if (time.time() - st.st_mtime) < (3600*24):
                    # Don't download again if dump file is < 24h old.
                    continue

            self.fetch_dump(f)

    def fetch_dump(self, filename):
        """ download dump file from ripe, write to /tmp """
        import requests

        url = "http://ftp.ripe.net/ripe/dbase/split/{}".format(filename)

        with open("/tmp/{}".format(filename), "wb") as handle:
            r = requests.get(url)

            for block in r.iter_content(8192):
                handle.write(block)

    def get_members(self, asset):
        """ recursively get members of as-set """
        members = []
        asset = asset.upper()

        if asset in self.assets:
            if asset in self.expanded:
                # avoid infinite loop
                return []
            for item in self.assets[asset]:
                if item["type"] == "aut-num":
                    members.append(item["data"])
                else:
                    self.expanded[item["data"]] = 1
                    for m in self.get_members(item["data"]):
                        members.append(m)
        else:
            # as-set not found :(
            pass
        return members

    def load_asset(self, name):
        members = []

        for member in self.get_members(name):
            asn = int(member.upper().replace("AS", ""))
            members.append(self.load_asn(asn))

        return ASSet(name, members=members)

    def load_asn(self, asn):
        import ipaddress
        inet = []
        inet6 = []

        if asn in self.inet:
            for i in self.inet[asn]:
                inet.append(ipaddress.ip_network(i))
        if asn in self.inet6:
            for i in self.inet6[asn]:
                inet6.append(ipaddress.ip_network(i))

        return ASNumber(asn, inet=inet, inet6=inet6)
