"""provides a Neighbor Cache implementation (and a bit more, like a prefix cache)
Allows the program to determine which packets to pass to the kernel

A cleanup thread is run in parallel and cleanup the old neighbor cache entries when they expire"""

from __future__ import with_statement
from subprocess import Popen, PIPE
from threading import RLock
from math import fabs

from NDprotector.Log import warn
import NDprotector
import NDprotector.Cleanup



# time after which a non updated entry in the NC is destroyed (in seconds)
TIMEOUT = 60

# a nonce should not live more than 2 seconds
NONCETTL = 2

def test_NC():
    # default values 
    NDprotector.mixed_mode = True
    NDprotector.retrans_timer = 1
    NDprotector.ts_delta = 300
    NDprotector.ts_fuzz = 1
    NDprotector.ts_drift = 0.01

    nc = NeighCache()
    timestamp = ICMPv6NDOptTimestamp(str(ICMPv6NDOptTimestamp())).timestamp

    # checking that we can not replay packets
    assert nc.update("2001::1", "aa:bb:cc:dd:ee:ff","binary public key", timestamp, True,) == True
    assert nc.update("2001::1", "aa:bb:cc:dd:ee:ff","binary public key", timestamp-10, True) == False
    assert nc.update("2001::1", "aa:bb:cc:dd:ee:ff","binary public key", timestamp+10, True) == True
    assert nc.update("2001::1", "aa:bb:cc:dd:ee:ff","binary public key", timestamp, True)  == False

    # trying to overwrite an unsecure entry
    assert nc.update("2001::1", "aa:bb:cc:dd:ee:ff","binary public key", timestamp+20, False) == False





def test_nonce_cache():
    nc = NeighCache()

    # for this test: 2001::1 is our node
    # 2001::2 and 2001::3 are neighbors

    assert nc.check_nonce_in("2001::2","2001::1","12345") == False
    nc.record_nonce_out("2001::1","2001::2","12345") 
    assert nc.check_nonce_in("2001::2","2001::1","12345") == True
    # the nonce, once checked should have been removed
    assert nc.check_nonce_in("2001::2","2001::1","12345") == False

    assert nc.pop_nonce_out("2001::1","2001::3") == None
    nc.record_nonce_in("2001::3","2001::1","123123")
    assert nc.pop_nonce_out("2001::1","2001::3") == "123123"

    # a nonce joined with a NS sent with a unspecified address (::)
    # will more likely be copied in a message destined to the All-Node
    # multicast address (ff02::1)
    nc.record_nonce_in("::","2001::1","123123")
    assert nc.pop_nonce_out("2001::1","ff02::1") == "123123"
    assert nc.pop_nonce_out("2001::1","ff02::1") == None


    # the solicitation was destined to the sollicited node multicast address
    # but the node will answer with its real address
    nc.record_nonce_in("2001::3","ff02::1:ff00:1","1231234")
    assert nc.pop_nonce_out("2001::1","2001::3") == "1231234"
    assert nc.pop_nonce_out("2001::1","2001::3") == None


    # for example: we send a NS to the solicited node multicast address and the
    # node answers using the unicast address
    nc.record_nonce_out("2001::1","ff02::1:ff00:2","123456") 
    assert nc.check_nonce_in("2001::2","2001::1","123456") == True
    nc.record_nonce_out("2001::1","ff02::1:ff00:2","123452") 
    assert nc.check_nonce_in("2001::2","2001::1","123456") == False

    # pretty close to what NS message would look like during DAD
    nc.record_nonce_out("::","ff02::1:ff00:2","123456") 
    assert nc.check_nonce_in("2001::2","ff02::1","123456") == True

    nc.record_nonce_in("::","ff02::1:ff00:1","1231234")
    assert nc.pop_nonce_out("2001::1","ff02::1") == "1231234"

def test_address_cache():
    """test all operations linked to the (shared) address cache"""
    # TODO update this test


    nc = NeighCache()
    orig_address = "something that looks like an address"

    nc.store_address(orig_address)
    address = nc.dump_addresses()[0] 
    assert address == orig_address

    nc.del_address(orig_address)
    nothing = nc.dump_addresses()
    assert nothing == [] 

def test_prefix_cache():
    """test all operations linked to the prefix cache"""
    # TODO update this test
    nc = NeighCache()

    prefix = "2001::"

    nc.update_prefix(prefix,42,42)
    assert nc.prefix[prefix] == (42,42)


def test_SSAO():
    """test all SSA option related operations"""

    nc = NeighCache()

    timestamp = ICMPv6NDOptTimestamp(str(ICMPv6NDOptTimestamp())).timestamp

    # we record a SSA for a specific node
    nc.update("fe80::1", "aa:bb:cc:dd:ee:ff","binary public key", timestamp, True, ([0,1], [9, 10, 11]))

    # we ask the neighbor cache about the capabilities of one of our neighbors 
    assert nc.get_ssao("fe80::1") == ([0, 1], [9, 10, 11])



class NeighCacheException(Exception):
    """exception raised when an unrecoverable event happens in the
    neighbor cache module"""
    pass

    


class NeighCache(object):
    """a neighbor cache (using the DP borg)"""

    __shared_state = {}

    def __init__(self):
        # DP borg, all instances share the same variables
        self.__dict__ = self.__shared_state
        # DP borg
        if not hasattr(self,"nd"):
            self.nd = {}
        if not hasattr(self,"lock"):
            self.lock = RLock()
        if not hasattr(self,"nonce_in"):
            self.nonce_in = {}
        if not hasattr(self,"nonce_out"):
            self.nonce_out = {}
        if not hasattr(self,"nilock"):
            self.nilock = RLock()
        if not hasattr(self,"nolock"):
            self.nolock = RLock()
        if not hasattr(self,"lock"):
            self.lock = RLock()
        if not hasattr(self,"addr"):
            self.addr = []
        if not hasattr(self,"addr_lock"):
            self.addr_lock = RLock()

        if not hasattr(self,"prefix"):
            self.prefix = {}
        if not hasattr(self,"prefix_lock"):
            self.prefix_lock = RLock()


    def update(self, address, mac_address, pubkey, timestamp, secured = False, ssao = ([], []) ):
        """update an entry if the new record is more secure or up-to-date than the old one"""

        TSnew = timestamp
        # local reception time of the packet
        RDnew = ICMPv6NDOptTimestamp(str(ICMPv6NDOptTimestamp())).timestamp


        # clocks must be loosely synchronized
        if TSnew and fabs( RDnew - TSnew) >= NDprotector.ts_delta:
            warn("current message's Timestamp is out of sync\n")
            return False


        # an unsecured entry can not be recorded when using strict mode
        if not secured and NDprotector.mixed_mode == False:
            return False

        with self.lock:
            try:
                old_params = self.nd[address] 
                (_, _, TSlast, oldsecured, oldssao, RDlast, _) = old_params

                if oldsecured and not secured:
                    # an unsecured entry will not overwrite a secure entry
                    warn("Trying to overwrite a secure NC entry with an unsecure entry\n")
                    return False


                if TSnew and TSnew + NDprotector.ts_fuzz <= \
                   TSlast + (RDnew - RDlast) * (1 - NDprotector.ts_drift) - NDprotector.ts_fuzz:
                    warn("current message has been replayed\n")
                    return False

            except KeyError:
                pass


            self.nd[address] = tuple([ mac_address, pubkey, TSnew, secured, ssao, RDnew, TIMEOUT] )

        return True



    # check_nonce_in and record_nonce_out are using the same list
    # pop_nonce_out and record_nonce_in are also using the same list
    # this is because solicitation and advertisement message are going in and
    # out or out and in
    # nonce_in and nonce_out are indexed by (our local address, neighbor address)

    def check_nonce_in(self,src,dst,nonce):
        """check if a message's nonce has an expected value. Remove the corresponding nonce when found.""" 

        # this is likely to be a response to a solicitation sent from the
        # unspecified address
        if dst == "ff02::1":
            dst = "::"
        with self.nolock:
            try:
                (nonce_list,ttl) =  self.nonce_out[(dst,src)]
                del nonce_list[nonce_list.index(nonce)]
                return True
            except (IndexError, AttributeError, KeyError,ValueError):
                pass

            # the message may have been sent to neighbor's the solicited node
            # multicast address
            try:
                src_nsma = inet_ntop(socket.AF_INET6,in6_getnsma(inet_pton(socket.AF_INET6,src)))
                (nonce_list,ttl) =  self.nonce_out[(dst,src_nsma)]
                del nonce_list[nonce_list.index(nonce)]
                return True
            except (IndexError, AttributeError, KeyError,ValueError):
                return False

    def record_nonce_in(self,src,dst,nonce):
        """record nonce value of any incomming solicitation message"""
        with self.nilock:
            nonce_list = []
            try:
                (nonce_list,ttl) = self.nonce_in[(dst,src)]
            except (IndexError, KeyError,ValueError):
                pass

            # appending the nonce to the already existing list
            nonce_list.append(nonce)
            self.nonce_in[(dst,src)] = (nonce_list, NONCETTL)



    def pop_nonce_out(self,src,dst):
        """return the nonce corresponding to a message exchange if possible, if
        none are available, None is returned"""

        if dst== "ff02::1":
            # because it was more likely recorded that way in the dict
            dst = "::"
        with self.nilock:
            try:
                (nonce_list,ttl) =  self.nonce_in[(src,dst)]
                return str(nonce_list.pop())
            except (IndexError, AttributeError, KeyError):
                pass
            try:
                # maybe the request that triggereds the registration in the cache
                # was a request to the sollicited node multicast address
                src_nsma = inet_ntop(socket.AF_INET6,in6_getnsma(inet_pton(socket.AF_INET6,src)))
                (nonce_list,ttl) = self.nonce_in[(src_nsma,dst)]
                return str(nonce_list.pop())
            except (IndexError, AttributeError, KeyError):
                return None

    def record_nonce_out(self,src,dst,nonce):
        """record nonce value of any incomming solicitation message"""
        with self.nolock:
            nonce_list = []
            try:
                (nonce_list,ttl) = self.nonce_out[(src,dst)]
            except (IndexError, KeyError,ValueError):
                pass
            # appending the nonce to the already existing list
            nonce_list.append(nonce)
            self.nonce_out[(src,dst)] = (nonce_list, NONCETTL)

    def store_address(self, addr):
        """record an address assigned to an interface"""
        with self.addr_lock:
            self.addr.append(addr)

    def dump_addresses(self):
        """output the list of the currently assigned addresses"""
        with self.addr_lock:
            return self.addr

    def del_address(self, addr):
        """delete an address (string) for the configured addresses on the interface"""
        with self.addr_lock:
            for addr_pos in range(len (self.addr)):
                if str(self.addr[addr_pos]) == addr:
                    del self.addr[addr_pos]

                    # there should not be twice the same address,
                    # we are safe to stop here
                    break

    def get_ssao(self, neigh):
        """query the Neighbor Cache for the value of the recorded SSA option"""
        with self.lock:
            try:
                (_, _, _, _, ssao, _, _) = self.nd[neigh]
                return ssao
            except KeyError:
                return ([], [])

    def update_prefix(self, prefix, preferred, valid):
        """Update the preferred and valid times of a prefix"""
        with self.prefix_lock:
            self.prefix[prefix] = (preferred, valid)


def cleaning_nc():
    nc = NeighCache()
    # warn("Cleaning Neighbor Cache\n")
    with nc.lock:
        for address, params in nc.nd.items():
            (mac_addr, pubkey, TSnew, secured, ssao, RDnew, ttl) = params
            if ttl <= 0:
                del nc.nd[address]
            else:
                nc.nd[address] = (mac_addr, pubkey, TSnew, secured, ssao, RDnew, ttl - 1)
    with nc.nilock:
        for address_tuple, (nonce_list,ttl) in nc.nonce_in.items():
            if ttl <= 0:
                del nc.nonce_in[address_tuple]
            else:
                nc.nonce_in[address_tuple] = (nonce_list,ttl - 1)

    with nc.nolock:
        for address_tuple, (nonce_list,ttl) in nc.nonce_out.items():
            if ttl <= 0:
                del nc.nonce_out[address_tuple]
            else:
                nc.nonce_out[address_tuple] = (nonce_list,ttl - 1)
    with nc.prefix_lock:
        addresses = nc.dump_addresses()

        for prefix in nc.prefix.keys():
            preferred, valid = nc.prefix[prefix]


            if preferred <= 0:
                # we currently do nothing, ideally
                # we could ask the address to pass
                # to the deprecated state
                pass

            # we remove the addresses corresponding to this prefix
            if valid <= 0:

                for address in addresses:
                    if address.is_autoconfigured and \
                       address.get_prefix() == prefix:
                        address.remove()
                        nc.del_address(str(address))
                del nc.prefix[prefix]
            else:
                nc.prefix[prefix] = (preferred - 1, valid -1)




    return

def NeighborCacheStart():
    # start the cleaning Thread for the NC
    NDprotector.Cleanup.cleanup_thread_subscribe(cleaning_nc)


    # register the currently assigned addresses
    nc = NeighCache()
    for addr in NDprotector.configured_addresses:
        nc.store_address(addr)

    #flushing all the old data from the kernel NC
    warn("flushing kernel neighbor cache\n")
    p = Popen( [ '/sbin/ip', '-6', 'neigh', 'flush', 'all' ], \
            stdout=PIPE, stderr=PIPE)
    if p.stdout.read() + p.stderr.read() != "":
        # raise an error
        raise NeighCacheException("unable to flush the kernel neighbor cache")




