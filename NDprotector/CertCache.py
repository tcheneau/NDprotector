"""contains a cache to store router's certificates
Two lists are kept: 
    - ApprovedCert which contains the certificate of router that provided a valid Certification Path
    - TBApprovedCert that temporarily store certificates that can't be yet verified

"""

from __future__ import with_statement
from NDprotector.Log import warn
import NDprotector, time, tempfile, os, hashlib
import NDprotector.Cleanup
from subprocess import Popen, PIPE
from threading import Thread, RLock
from contextlib import nested
from signal import SIGINT, SIGKILL, signal, SIG_IGN
from scapy6send.cert import *


# after this period, an unverifiable Certificate Path is discarded
TIMEOUT = 60

def test_CertCache():
    # verifying the certificate validation process
    NDprotector.trustanchors = [ "examples/test/cacert.pem" ]


    # we consider that we have the X.509 extensions
    # for IP  addresses
    NDprotector.x509_ipextension = True
    
    # we do not test the ECC support
    NDprotector.ECCsupport = False

    # certificate's Public Key
    for ta in NDprotector.trustanchors:
        with open("examples/test/level1-cert.pem") as f:
            certl1 = f.read()
        with open("examples/test/level2-cert.pem") as f:
            certl2 = f.read()

        certl2 = Cert(certl2).output("DER")

        cc = CertCache()
        cc2 = CertCache()

        cc.storecert(1,certl1)
        cc.storecert(1,certl2)

        
        # no certificate have been verified yet
        assert len(cc.ApprovedCert) == 0

        # this certificate path is correct and 
        # triggers an entry creation in the Approved Certificate list
        cc.checkcertpath(1)
        assert len(cc.ApprovedCert) == 1


        # this certificate path is uncompleted and
        # does not modify anything
        cc.storecert(2,certl2)
        cc.checkcertpath(2)
        assert len(cc.ApprovedCert) == 1


        certl2 = Cert(certl2)
        # prefix authorized by the cert
        prefixes =  ["2001:aaaa:bbbb::"] # /48
        pk_hash = sha.sha(certl2.key.derkey).digest()[:16]

        # the 0 means RSA/SHA-1
        assert cc.trustable_hash(pk_hash, prefixes, 0)

        prefixes =  ["2001:aaaa:cccc::"] # /48
        assert not cc.trustable_hash(pk_hash, prefixes, 0)


        cc.storeid(4242)
        assert cc2.id_match(4242)

        assert cc.id_match(2424) == False

def test_helper_func():
    addr1_int = addr_to_int("2001:660::")
    addr2_int = addr_to_int("2001:600::")
    addr3_int = addr_to_int("2001::")

    assert (addr1_int & prefix_mask(16)) == (addr2_int & prefix_mask(16))
    assert (addr1_int & prefix_mask(19)) == (addr2_int & prefix_mask(19))
    assert (addr2_int & prefix_mask(22)) != (addr3_int & prefix_mask(22))

def addr_to_int(addr_str):
    """An help function that convert a printable address into
    the int number corresponding to that address"""

    addr_net = socket.inet_pton(socket.AF_INET6,addr_str)
    addr_int = 0
    for s in addr_net:
        addr_int = addr_int * 256 + ord(s)
    return addr_int

def prefix_mask(lenght):
    """return a prefix legnth that matches the first "lenght" bit of the address"""
    return (2**128-1)-(2**(128-lenght) -1)


class CertCache(object):
    """a certificate cache (using the DP borg)"""

    __shared_state = {}

    def __init__(self):
        # DP borg: all instances share the same variables
        self.__dict__ = self.__shared_state
        
        if not hasattr(self,"ApprovedCert"):
            self.ApprovedCert = []
        if not hasattr(self,"ApprLock"):
            self.ApprLock= RLock()


        if not hasattr(self,"TBApprovedCert"):
            self.TBApprovedCert = {}
        if not hasattr(self,"TBApprLock"):
            self.TBApprLock = RLock()

        if not hasattr(self,"Id"):
            self.Id = {}
        if not hasattr(self,"IdLock"):
            self.IdLock = RLock()

        # control the TBapprovedCert cache cleaning
        if not hasattr(self,"clean"):
            self.clean = True


    def storeid(self,id):
        """store the Identifier when sending a CPS"""
        warn("storing ID %d for a new CPS\n" % id)
        with self.IdLock:
            self.Id[id] = TIMEOUT

    def id_match(self,id):
        """verifies that a Identifier carried in a CPA 
        matches a sent CPS"""
        warn("checking ID %d against a previously sent CPS\n" %  id)
        with self.IdLock:
            return id in self.Id


    def storecert(self,id,cert):
        """temporarly store certs, they are sorted by their ID"""
        warn("storing on cert for Certificate Path #%d\n" % id)

        with self.TBApprLock:
            certpath = []
            ttl = TIMEOUT
            try:
                (certpath, oldttl) = self.TBApprovedCert[id]

            except KeyError:
                pass
            certpath.append(Cert(cert))
            self.TBApprovedCert[id] = (certpath, ttl)

    def checkcertpath(self,id):
        """check if a complete cert path is valid,
        if it is, the last cert is moved to the ApprovedCert list
        if it isn't, it is discarded"""
        
        warn("Verifying certification path for #%d\n" % id)

        with self.TBApprLock:

            try:


                valid_path = False

                certs, _ = self.TBApprovedCert[id]

                # removes everything if the last certificate in the chain
                # is already trusted
                already_trusted = False

                with self.ApprLock:
                    for accepted_cert in [ c.output("DER") for c in self.ApprovedCert ] :
                        if accepted_cert == certs[-1].output("DER"):
                            warn("The Certificate Path we received is already trusted\n")
                            already_trusted = True

                if not already_trusted:
                    # we concat all the cert we got in a new file
                    cert_desc, certfilename = tempfile.mkstemp()

                    valid_IPExt = True

                    if NDprotector.x509_ipextension:
                        # we check that each certificate includes the previous one
                        # each certificate are expected to carry an IP extension

                        # address with only 1s
                        (prev_addr,prev_preflen) = certs[0].IPAddrExt
                        prev_addr = addr_to_int(prev_addr)

                        try:
                            for cert in certs:
                                (addr,preflen) = cert.IPAddrExt

                                addr = addr_to_int(addr)

                                if (addr & prefix_mask(prev_preflen)) == \
                                        (prev_addr & prefix_mask(prev_preflen)) and \
                                            prev_preflen <= preflen :
                                    prev_addr = addr
                                    prev_preflen = preflen

                                # this prefix is not contained inside its parent's certificate
                                else:
                                    warn("Certificate's IP extension does not"
                                         " match its parent's Certificate\n")
                                    valid_IPExt = False
                                    break



                        # if we get in there, it probably means that one certificate is lacking
                        # of IP address extension
                        except TypeError:
                            warn("At least one certificate in the chain seems "
                                 "to lack of the X.509 Extensions for IP Address\n")
                            valid_IPExt = False


                    if valid_IPExt:
                        for cert in certs:
                            os.write(cert_desc,cert.output(fmt="PEM"))
                        os.close(cert_desc)

                        for ta in NDprotector.trustanchors:
                            tacert = Cert(ta)

                            # we copy the TA in a temporary file
                            ca_desc, cafilename = tempfile.mkstemp()
                            os.write(ca_desc, tacert.output(fmt="PEM"))
                            os.close(ca_desc)



                            # XXX double check this command
                            # we ask openssl to check the certificate for us
                            cmd = "openssl verify -CAfile %s %s" % (cafilename,certfilename)
                            res = Popen(cmd, stdout=PIPE, shell=True)

                            output = res.stdout.read()

                            # we clean all the temporary files
                            os.unlink(cafilename)

                            if "OK" in output:
                                valid_path = True
                                break

                        os.unlink(certfilename)


                        if valid_path:
                            warn("We received a complete and valid Certification Path\n")
                            with self.ApprLock:


                                # only the last certificate from the chain is valuable
                                self.ApprovedCert.append(certs[-1])

                # either way, we remove the cert path that has been processed
                del self.TBApprovedCert[id]
            except KeyError:
                pass
        with self.IdLock:
            try:
                del self.Id[id]
            except KeyError:
                pass

    def trustable_hash(self,hash_cert, prefixes, sigtypeID):
        """check if a hash contained in a RSA signature option corresponds to a trustable certificate
        Also check if the certificate's IP Addr extension matches to the advertised prefixes"""

        hashfunc = getattr(hashlib, SigTypeHashfunc[sigtypeID])
        try:
            with self.ApprLock:
                # case #1: we have accepted a certificate for these prefixes
                for cert in self.ApprovedCert:
                    if NDprotector.x509_ipextension:
                        (addr,preflen) = cert.IPAddrExt
                        addr = addr_to_int(addr)

                    if hash_cert == hashfunc(cert.key.derkey).digest()[:16]:
                        if NDprotector.x509_ipextension: 
                            for prefix in\
                                    (((addr_to_int(p) & prefix_mask(preflen)) for p in prefixes)):
                                        if prefix != (addr & prefix_mask(preflen)):
                                            return False
                            else:
                                return True
                        elif not NDprotector.x509_ipextension:
                            return True

            # case #2: the certificate linked to the messages
            # is directly a trust anchor
            for certfile in NDprotector.trustanchors:
                cert = Cert(certfile)
                if NDprotector.x509_ipextension:
                    (addr,preflen) = cert.IPAddrExt
                    addr = addr_to_int(addr)
                if hash_cert == sha.sha(cert.key.derkey).digest()[:16]:
                    if NDprotector.x509_ipextension:
                        for prefix in ((addr_to_int(p) & prefix_mask(preflen) for p in prefixes)):
                            if prefix != (addr & prefix_mask(preflen)):
                                return False
                            else:
                                return True
                    elif not NDprotector.x509_ipextension:
                        return True
        # likely due to a missing IP Addr extension
        except TypeError:
            warn("The verified certificate most likely "
                 "does not have any IP addresses extension field\n")
        return False

    def close_cleaning_thread(self):
        """when the program is exiting, we need to close the cleaning thread"""
        self.clean = False

def cleaning_certcache():
    """a thread that cleans the Certificate cache regularly"""
    cc = CertCache()

    with cc.IdLock:
        for id, value in cc.Id.items():
            cc.Id[id] = value - 1
            if cc.Id[id] <= 0:
                # TTL has reached its limit, remove the entry
                del cc.Id[id]


    with cc.TBApprLock:
        for id, misc in cc.TBApprovedCert.items():
            (certs, ttl) = misc

            if ttl <=0:
                del cc.TBApprovedCert[id]
            else:
                cc.TBApprovedCert[id] = (certs, ttl - 1)


def CertCacheStart():
    # start the cleaning Thread for the CC
    NDprotector.Cleanup.cleanup_thread_subscribe(cleaning_certcache)

    # to ensure default values are initialized
    CertCache()

