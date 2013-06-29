import random, socket, NDprotector, os, time, math
from socket import inet_pton, inet_ntop
from Log import warn
from Tool import SigAlgList_compute, load_pkey, load_key
from Plugin import get_plugins_by_capability
from NDprotector.NeighCache import NeighCache
from scapy6send.scapy6 import *
from subprocess import Popen, PIPE

try:
    from scapy6send.ecc import ECCkey
except ImportError:
    pass




# path to the various neede binairies
IPpath="/sbin/ip"
OpenSSL="/usr/bin/openssl"

def test_binaries():
    assert os.path.isfile(IPpath)
    assert os.path.isfile(OpenSSL)

def test_Address():
    """test the address creation (static and dynamic)"""

    # locally override the default config for the tests
    try:
        NDprotector.assign_addresses
    except AttributeError:
        NDprotector.assign_addresses = False

    try:
        NDprotector.default_publickey
    except AttributeError:
        NDprotector.default_publickey = None
    try:
        NDprotector.rsa_key_size
    except AttributeError:
        NDprotector.rsa_key_size=1024

    try:
        NDprotector.ECCsupport
    except AttributeError:
        NDprotector.ECCsupport = False

    # static address creation
    a = Address(address = "fe80::2cdc:64d3:7330:3209", key = "examples/test/test_key.pem", \
            modifier = 64897927265332714218123184968256009153L , sec = 1)
    # these elements are private and should not be accessed directly normaly
    assert a.__dict__['_Address__modifier'] == 64897927265332714218123184968256009153L
    assert a.__dict__['_Address__sec'] == 1
    assert a.__dict__['_Address__prefix'] == "fe80::"
    assert str(a) == "fe80::2cdc:64d3:7330:3209"
    assert a.get_prefix() == "fe80::"

    assert a.sign_doable([0,1]) == 1
    assert a.sign_doable([1,0]) == 1
    assert a.sign_doable([9,10]) == None

    # dynamic address construction
    b = Address(prefix = "fe80::",  sec = 1) 
    assert b.__dict__['_Address__sec'] == 1
    assert b.__dict__['_Address__prefix'] == "fe80::"

    

class DadException(Exception):
    """Exception raised when the duplicate address detection (DAD) proccess
    fails more than 3 times.
    Likely to occur during an attacke or hen the nodes are misconfigured (the
    same configuration was used for different nodes)"""
    pass

class AddressException(Exception):
    """Exception raised for any error related to the address creation process"""
    pass



class Address:
    """manage CGA address creation, DAD, address removal on an interface An
    address could be created from only an interface identifier, a prefix and a
    public key different configuration can happen depending if the address was
    already generated or need to be generated
    
    
    - interface: interface on which the address will be assigned
    - address: if available, the address that the node request, it involves
      that the different CGA parameters are passed too (modifier, etc)
    - prefix: if the address mmust be retrieve through SLAAC  (can not be used
      if address is set
    - key: the raw DER Private key  or a file containing the Private Key (DER
      or PEM format accepted). 
      If no "publickey" argument is specified, the public key linked to this key
      is stored in the Public Key field of the CGA PDS
    - modifier: modifier
    - collcountt: collision counter
    - ext: (optional) extension to the CGA Parameters data structure (currently unsupported)
    - keypos: (optional) indicate the position of the real key used to sign the messages
    - publickey: it indicates a Public Key that must be stored in the Public Key field of the CGA PDS
      This value is ignored when no "key" argument is specified
    - autoconf: indicates whether the address is genereted by the Stateless Address Autoconfiguration
    - dad: indicates if the initialisation code must perform Duplicate Address Detection or not
    """

    def __init__(self,interface=None,\
            address=None,prefix=None,\
            key=None,modifier=None,sec=None,\
            collcount=0, ext=None, keypos=0,\
            publickey=None,\
            autoconf=False, dad=True,\
            ** extrap):
        """if no interface name is given,
        we'll use scapy6send to determine
        a working one and use it"""

        self.__interface = None
        self.__address = None
        self.__prefix = None
        self.__key = None
        self.__pubkey = None
        self.__modifier = 0
        self.__collcount = 0
        self.__sec = 0
        self.__ext = []
        self.__keypos = keypos
        self.__autoconf = autoconf

        # we can't put ext=[] as a default argument because of its "mutable" nature
        if ext == None: ext = []
        
        self.__ext = ext

        plugins = get_plugins_by_capability("Address")

        for plugin in plugins:
            plugin.init_address(self,extrap)

        # time at the beginning of the function
        beginning = time.time()

        if not address and not prefix:
            raise Exception("can not configure an address without at least a prefix")
        if address and (not key or (not modifier and modifier !=0 )):
            raise Exception("can not use an address without at least the key and the modifier")
        if interface == None:
            warn("no interface name given, using %s\n" % conf.iface)
            self.__interface = conf.iface
        else:
            if interface in get_if_list():
                self.__interface = interface
            else:
                raise AddressException("No such interface for the address: %s", interface)
        
        if collcount >= 0 and collcount <= 3:
            self.__collcount = collcount
        else:
            raise AddressException("The collision counter must be between 0 and 3")

        if modifier == None:
            self.__modifier= random.randint(0,2**128 -1)
        else:
            self.__modifier= modifier

        if sec !=  None:
            self.__sec=sec
        else:
            self.__sec=NDprotector.default_sec_value

        if prefix:
            # prefix length is /64
            if socket.inet_pton(socket.AF_INET6,prefix)[8:] == \
                    '\x00'*8 :
                self.__prefix == prefix
            else:
                raise AddressException("prefix %s is not valid" % prefix)

        # generate a key or use a default one when none is passed
        if key is None and NDprotector.default_publickey:
            self.__key = load_key(NDprotector.default_publickey, NDprotector.ECCsupport)
            self.__pubkey = load_pkey(NDprotector.default_publickey, NDprotector.ECCsupport)

        elif key is None and not NDprotector.default_publickey:
            warn("Computing an RSA key pair\n")
            k = Popen( [ OpenSSL , "genrsa", str(NDprotector.rsa_key_size)], stdout=PIPE, stderr=PIPE)
            key = k.stdout.read()
            if not "BEGIN RSA PRIVATE KEY" in key:
                raise AddressException("unable to compute the RSA public Key")
            self.__key = Key(key)
            self.__pubkey = self.__key.toPubKey()

        # a key was passed
        else: 
            self.__key  = load_key(key, NDprotector.ECCsupport)
            self.__pubkey = load_pkey(key, NDprotector.ECCsupport)

        # set the Public Key that will be store in the CGA PDS
        # in the Public Key field
        if publickey:
            self.__pubkey = load_pkey(NDprotector.default_publickey, NDprotector.ECCsupport)


        if address == None:
            self.__prefix = prefix
            warn("Generating CGA\n")
            if type(modifier) == int:
                modifier = pkcs_i2osp(modifier,16)
            res = CGAgen(prefix, self.__pubkey, self.__sec, modifier = modifier, ext=ext, do_dad=False)
            if type(res) is tuple:
                (self.__address,param) = res
                self.__modifier =  pkcs_os2ip(param.modifier)
            else:
                raise AddressException("failed to create an address, perhaps you should investage on the public key files")
        else:
            # we use the address passed in parameter
            self.__address = address

            # weak TODO: find something cleaner to extract the prefix from the address
            self.__prefix = socket.inet_ntop(socket.AF_INET6, \
                    socket.inet_pton(socket.AF_INET6,address)[:8]+"\x00"*8)
            modifier = pkcs_i2osp(self.__modifier,16)

            self.__sec = ord(socket.inet_pton(\
                socket.AF_INET6,self.__address)[8]) >> 5

            if not CGAverify(self.__address, CGAParams(modifier=modifier, prefix=self.__prefix, \
                            ccount = self.__collcount, pubkey = self.__pubkey, \
                            ext = ext)):
                raise AddressException("Address %s is not a valid CGA" % self.__address)
        if NDprotector.assign_addresses:
            self.assign(dad=dad)

        end = time.time()
        warn("CGA address %s computed and assigned in %f seconds\n" %\
                (self.__address, end - beginning))


    def __str__(self):
        """print an traditionnal IPv6 hexadecimal representation of the address"""
        if self.__address:
            return self.__address
        else:
            return ""

    def config_dump(self):
        """print informations on the structure in the same format as the config file"""

        ext_out = [ "[" ]
        for ext in self.__ext :
            ext = CGAExt(str(ext))
            ext_out.append( " CGAExt(etype = " )
            ext_out.append( str(ext.etype) )
            ext_out.append( ", elen = " )
            ext_out.append( str(ext.elen) )
            ext_out.append( ", edata = \"" )
            ext_out.append( str(ext.edata) )
            ext_out.append( "\")," )
        ext_out.append ( "]" )

        ext_out = "".join(ext_out)

        ret = "# Address is %s\n" \
              "# copy/paste from here to your NDprotector.configured_addresses\n" \
              "Address( interface = '%s', address='%s', modifier = %iL, collcount = %i, sec = %i, ext= %s, key= %s)" \
                % (self.__str__(), self.__interface, self.__address, self.__modifier, self.__collcount, self.__sec, ext_out, `self.__key.pemkey`)
                
        return ret

    def do_dad(self):
        """perform the duplicate address detection (DAD) proccess as described in RFC4861 and updated in RFC3971"""
        while self.__collcount < 3:
            # send MLD to receive packets destined to our tentative address
            # FIXIT: it seems that scapy6send does not handle MLD report message correctly for now
            # investigate on this

            # we need this value on the forked process too, so we compute it
            # before the fork
            nonce = "".join([ chr(random.randrange(255))  for i in range(6)])

            # the father process sniff (potentials) DAD packets while the
            # children one send a NS
            pid = os.fork()

            # the filters of sniff() function works better when conf.iface is
            # not a tun (could be the case if the node uses an IPv6 tunnel
            old_if = conf.iface
            conf.iface = self.__interface

            if pid == 0:
                # send a NS toward the solicited node multicast address
                time.sleep(0.2) # to be sure the capture mode is already on

                cgapds = CGAParams(modifier = pkcs_i2osp(self.__modifier, 16), \
                        prefix = self.__prefix, \
                        ccount = self.__collcount, \
                        pubkey = self.__pubkey, \
                        ext = self.__ext)

                p = str( IPv6(src = "::",dst = inet_ntop(socket.AF_INET6, # dst is the solicited node multicast address
                         in6_getnsma(inet_pton(socket.AF_INET6, self.__address))))/
                         ICMPv6ND_NS(tgt = self.__address) )
                p = Ether(src=get_if_hwaddr(self.__interface)) / self.sign(p,dad=True,nonce=nonce)

                sendp(p,iface=self.__interface,verbose=NDprotector.verbose)
                os._exit(0)
            else:
                # listen (sniff) to packets destined to the solicited node multicast address and the tentative address itself
                hwaddr = get_if_hwaddr(self.__interface)

                packets = sniff(timeout=NDprotector.retrans_timer, \
                                iface=self.__interface, \
                                filter="icmp6 and not ether src %s" % hwaddr, \
                                lfilter= lambda x: x.haslayer(ICMPv6ND_NS) or x.haslayer(ICMPv6ND_NA))
                collision = False
                for packet in packets:
                    # we only threat  NS and NA NS and NA
                    if (packet.haslayer(ICMPv6ND_NS) and \
                        packet.getlayer(IPv6).src=="::" and \
                        packet.getlayer(ICMPv6ND_NS).tgt == self.__address)  \
                        or \
                        (packet.haslayer(ICMPv6ND_NA) and packet.getlayer(ICMPv6ND_NA).tgt==self.__address):
                            if self.__collcount==0:
                                collision=True
                                break  # from RFC 3971: first time when perform DAD, we listen for unsecure NDP messages
                            else: 

                                try:
                                    address = packet[IPv6].src 

                                    # we can receive messages from other node performing the DAD
                                    if packet.haslayer(ICMPv6ND_NS) and address == "::":
                                        address = packet.tgt
                                    # CGA address check
                                    if not  CGAverify(address,packet[CGAParams]):
                                        warn("one packet with an invalid CGA address was received during the DAD procedure\n")
                                        continue

                                    # signature check
                                    if not packet[ICMPv6NDOptUSSig].verify_rsa_sig(packet[CGAParams].pubkey):
                                        warn("one packet failed signature check during the DAD process\n")
                                        continue

                                    if packet.haslayer(ICMPv6ND_NS) and packet.getlayer(ICMPv6NDOptNonce).nonce == nonce:
                                        warn("one packet is a replayed packet (potentially under a DAD DOS replay attack\n")
                                        continue

                                    if packet.haslayer(ICMPv6ND_NA) and packet.dst != "ff02::1" and packet.getlayer(ICMPv6NDOptNonce).nonce != nonce :
                                        print "expect %s" % `nonce`
                                        print "received %s" % `packet.getlayer(ICMPv6NDOptNonce).nonce`
                                        warn("NA value does not match the nonce from the NS\n")
                                        continue

                                    # quick and dirty way to obtain the "current" time
                                    ts = ICMPv6NDOptTimestamp(str(ICMPv6NDOptTimestamp())).timestamp

                                    # nodes need to have a loosely synchronised clock
                                    if math.fabs(packet.getlayer(ICMPv6NDOptTimestamp).timestamp - ts) > NDprotector.ts_delta:
                                        warn("Timestamp value exceed the delta\n")
                                        continue

                                except AttributeError: # where likely to go in there if one option is missing
                                    continue # in this case, we ignore the packet


                                # weak TODO so far, the packet seems legit,
                                # need create/update an entry in the Neighbor
                                # Cache (so the Timestamp value is recorded)


                                collision=True
                                break 

                os.wait()

                conf.iface = old_if


                if collision==True:
                    self.__collcount += 1
                    warn("collision on %s detected\n" % self.__address)

                    (self.__address,_) = CGAgen1(self.__prefix, \
                                                self.__pubkey, \
                                                self.__sec, \
                                                self.__ext, \
                                                pkcs_i2osp(self.__modifier,16), \
                                                self.__collcount)
                    warn("trying DAD on new address %s\n" % self.__address)

                # no collision, DAD has been performed correctly
                else:
                    return

        raise DadException("Duplicate Address Detection for %s failed, likely due to an attack or a misconfiguration" % self.__address)


    def is_autoconfigured(self):
        """if the address is generated during autoconfiguration or not"""
        return self.__autoconf

    def assign(self,dad=True):
        """assign the actual address to the interface"""
        if dad:
            self.do_dad() # the address can change during this process

        # this is the first CGA on the interface, we flush the addresses
        if NDprotector.flush_interfaces and NDprotector.currently_used_interfaces[self.__interface] == 0:
            # flush the addresses on the interface
            warn("flushing all addresses on interface %s\n" % self.__interface)
            ex = Popen([ IPpath, "-6", "addr", "flush", 
                                  "dev", str(self.__interface)], stderr=PIPE)
            ex.stderr.read()

        # adding reference count on the interface
        NDprotector.currently_used_interfaces[self.__interface] +=1

        warn("assigning %s to interface %s\n" % (self.__address,self.__interface))
        # "nodad" is passed as we performed the dad ourself already
        ex = Popen([ IPpath, "-6", "addr", "add", 
                              "dev", self.__interface,
                              self.__address + "/64","nodad"], stderr=PIPE)
        status = ex.stderr.read()
        if status == 'RTNETLINK answers: Operation not permitted\n':
            raise AddressException("unable to assign the address (perhaps you don't have the root priviledge")
        elif status == 'RTNETLINK answers: File exists\n' :
            warn("The address has already been assigned to the interface\n")

    def modify(self, valid_lft="forever", preferred_lft="forever"):
        """set the valid and preferred lifetime of an address
        "forever" is a valid value for valid_lft and preferred_lft"""

        warn("changing valid and prefered of %s to %s and %s\n"\
               % (self.__address, str(valid_lft), str(preferred_lft)))


        # enable a new address
        ex = Popen([ IPpath, "-6", "addr", "change", 
                              "dev", self.__interface,
                              self.__address + "/64",
                              "valid_lft", str(valid_lft),
                              "preferred_lft", str(preferred_lft)],stderr=PIPE)
        _ = ex.stderr.read()



    def remove(self):
        """remove the address from the interface"""
        warn("removing %s from interface %s\n" % (self.__address,self.__interface))
        ex = Popen([ IPpath, "-6", "addr", "del",
                     "dev", self.__interface, self.__address + "/64"],stderr=PIPE)
        # most likely, the program does not run with the root identity
        status = ex.stderr.read()

        # removing reference count on the interface
        NDprotector.currently_used_interfaces[self.__interface] -=1

        if status == 'RTNETLINK answers: Operation not permitted\n':
            raise AddressException("unable to remove the address (perhaps you don't have the root priviledge")
        elif status == 'RTNETLINK answers: Cannot assign requested address\n':
            warn("The address has already been removed\n")

    def sign_doable(self, verifiable_sigtypeID):
        """return a sigtypeID if a the address is bound to a key that 
        can sign a signature algorithm matching one in the verifiable_sigtypeID list"""

        for sigtype in self.__key.get_sigtypeID():
            if sigtype in verifiable_sigtypeID:
                return sigtype

        return None

    def sign(self,data, dad=False, nonce=None):
        """sign the data with RSA signature option, adds timestamp, nonce, etc.
        Data must be a valid NS, NA, RS, RA or ICMPv6 redirect packet"""
        ndp_msg = IPv6(data)

        if dad and ndp_msg[IPv6].src != "::" :
            raise AddressException("tried to sign a DAD message with the null address")
        elif not dad and ndp_msg[IPv6].src != self.__address:
            raise AddressException("tried to sign a message with an incorrect source address")


        if not ndp_msg.haslayer(ICMPv6ND_RS) \
           and not ndp_msg.haslayer(ICMPv6ND_RA) \
           and not ndp_msg.haslayer(ICMPv6ND_NS) \
           and not ndp_msg.haslayer(ICMPv6ND_NA) \
           and not ndp_msg.haslayer(ICMPv6ND_Redirect) :
           raise AddressException("tried to sign a packet that is not a NDP message")


        # TODO:
        # for now, we only take the first algorithm of the list,
        # latter, we will implement a round-robin mechanism
        nc = NeighCache()
        ( sign, verif ) = nc.get_ssao(ndp_msg.dst)
        neigh_sigalg = (sign + verif)
        sigtypeID = self.sign_doable(neigh_sigalg)
        if sigtypeID == None:
            if NDprotector.ECCsupport and isinstance(self.__key,ECCkey):
                sigtypeID = self.__key.get_sigtypeID()[0]
                warn("No matching Signature Algorithm to sign the message, using %s\n" \
                       % SigTypeID[sigtypeID])
            else:
                warn("No matching Signature Algorithm to sign the message, using RSA/SHA-1\n")
                sigtypeID = 0


        cgapds = CGAParams(modifier = pkcs_i2osp(self.__modifier, 16), \
                prefix = self.__prefix, \
                ccount = self.__collcount, \
                pubkey = self.__pubkey, \
                ext = self.__ext)
        # in some case, we may not really want to add a nonce value
        if nonce is None:
            # no nonce value are joined with this message
            ndp_msg /= ICMPv6NDOptCGA(cgaparams = cgapds) / \
                       ICMPv6NDOptTimestamp()
        else:

            # add the different options to a message 
            ndp_msg /= ICMPv6NDOptCGA(cgaparams = cgapds) / \
                       ICMPv6NDOptTimestamp() / \
                       ICMPv6NDOptNonce(nonce=nonce) 

        # compute the available Signature Algorithms
        sigalgs = SigAlgList_compute(sigtypeID, NDprotector.SignatureAlgorithms)

        ndp_msg /= ICMPv6NDOptSSA(sigalgs=sigalgs)

        # dirty hack: force the update of the payload length
        extra_payload_len = len(str(ndp_msg.getlayer(ICMPv6NDOptCGA)))
        ndp_msg[IPv6].plen += extra_payload_len

        # dirty hack: force to recompute the (ICMP) checksum
        del(ndp_msg[IPv6].payload.cksum)

        # freezing data inside the new option fields
        ndp_msg = IPv6(str(ndp_msg))

        # need to bind the key hash with address' PubKey
        pubkey = load_pkey(self.__key, NDprotector.ECCsupport)

        keyh = get_public_key_hash(pubkey, sigtypeID=sigtypeID)

        # adding the signature
        ndp_msg /= ICMPv6NDOptUSSig(key=self.__key, pos = self.__keypos,
                keyh = keyh, sigtypeID=sigtypeID)
        


        # dirty hack: force the update of the payload length
        extra_payload_len = len(str(ndp_msg.getlayer(ICMPv6NDOptUSSig)))
        ndp_msg[IPv6].plen += extra_payload_len


        # dirty hack: force to recompute the (ICMP) checksum (once again)
        del(ndp_msg[IPv6].payload.cksum)


        return ndp_msg


    def get_interface(self):
        return self.__interface

    def get_prefix(self):
        return socket.inet_ntop(socket.AF_INET6,socket.inet_pton(socket.AF_INET6,self.__address)[:8] + "\x00"*8)


