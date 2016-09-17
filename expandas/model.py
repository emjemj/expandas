class ASSet:
    def __init__(self, name, **kwargs):
    
        if not "members" in kwargs:
            raise Exception("Please supply a list of members")

        self.name = name
        self.members = kwargs["members"]
        self.inet = []
        self.inet6 = []

        # Copy member prefixes to our own prefix list
        for member in self.members:
            self.inet += member.inet
            self.inet6 += member.inet6

    def __str__(self):
        return self.name

    def __repr__(self):
        return "ASSet('{}', members={})".format(self.name, self.members)

    def __iter__(self):
        for member in self.members:
            yield member

    def __len__(self):
        return len(self.members)

    def __contains__(self, item):
        import ipaddress

        if type(item) is int:
            # Assume integer argument is an ASN.
            return [ a for a in self.members if a.asn == int(item) ]
        elif type(item) is ASNumber:
            return item in self.members
        elif type(item) is str:
            # Assume str argument is an ip network
            ip = ipaddress.ip_network(item)

            if ip.version == 4:
                lst = self.inet
            else:
                lst = self.inet6

            for i in lst:
                if i.overlaps(ip):
                    return True
            return False
        else:
            return False

class ASNumber:
    def __init__(self, asn, **kwargs):

        if not "inet" in kwargs:
            raise("Please supply a list of inet prefixes")
        if not "inet6" in kwargs:
            raise("Please supply a list of inet6 prefixes")

        self.asn = int(asn)
        self.inet = kwargs["inet"]
        self.inet6 = kwargs["inet6"]

    def __str__(self):
        return "AS{}".format(self.asn)

    def __repr__(self):
        return "ASNumber({}, inet={}, inet6={})".format(self.asn, self.inet, self.inet6)

    def __contains__(self, item):
        import ipaddress

        if type(item) is str:
            ip = ipaddress.ip_network(item)

            if ip.version == 4:
                lst = self.inet
            else:
                lst = self.inet6

            for i in lst:
                if i.overlaps(ip):
                    return True
        return False

    def __iter__(self):
        for ip in self.inet + self.inet6:
            yield ip

    def __len__(self):
        return len(self.inet + self.inet6)
