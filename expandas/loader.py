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
        if os.path.isfile(t_path) and os.access(t_path, os.X_OK):
            return t_path

        # Last of all check $PATH environment variable
        if not bgpq3_path:
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

        if r.status_code != requests.codes.ok:
            raise Exception("Something went wrong")

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
                asn = int(attr["value"].replace("AS", ""))
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

        members = []
        # This could probably do with some error handling
        for attr in r.json()["objects"]["object"][0]["attributes"]["attribute"]:
            if attr["name"] == "members":
                members.append(attr)
        return members
