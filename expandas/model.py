class BaseModel:
    """ Abstract base model, implements methods used by both ASSet and ASNumber """

    def contains(self, inet):
        """ Check if as-set or asnumber contains a specified network """
        import ipaddress
        ip = ipaddress.ip_network(inet)

        if ip.version == 4:
            for i in self.inet:
                if i.overlaps(ip):
                    return True
            return False
        elif ip.version == 6:
            for i in self.inet6:
                if i.overlaps(ip):
                    return True
            return False

class ASSet(BaseModel):
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

    def contains_asn(self, asn):
        if [ a for a in self.members if a.asn == int(asn) ]:
            return True
        return False

class ASNumber(BaseModel):
    def __init__(self, asn, **kwargs):

        if not "inet" in kwargs:
            raise("Please supply a list of inet prefixes")
        if not "inet6" in kwargs:
            raise("Please supply a list of inet6 prefixes")

        self.asn = int(asn)
        self.inet = kwargs["inet"]
        self.inet6 = kwargs["inet6"]
