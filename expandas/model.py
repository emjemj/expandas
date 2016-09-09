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

class ASNumber:
    def __init__(self, asn, **kwargs):

        if not "inet" in kwargs:
            raise("Please supply a list of inet prefixes")
        if not "inet6" in kwargs:
            raise("Please supply a list of inet6 prefixes")

        self.asn = asn
        self.inet = kwargs["inet"]
        self.inet6 = kwargs["inet6"]
