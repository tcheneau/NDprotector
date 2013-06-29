"""A plugins that implements epheremal addresses"""

import NDprotector, sys
from NDprotector.Plugin import Plugin
from NDprotector.Log import warn
from NDprotector.Address import Address
from NDprotector.NeighCache import NeighCache
from NDprotector.Cleanup import cleanup_thread_subscribe
from socket import AF_INET6
from subprocess import Popen, PIPE
from contextlib import nested
from threading import RLock

if "lib" not in sys.path:
    sys.path.append("lib")
import nfqueue

IPTABLES = "/sbin/ip6tables"

def test_plugin():
    """unitary tests for the function that composes the module"""

    e1 = EphemeralAddress()
    e2 = EphemeralAddress()

    assert e1.get_name() == e2.get_name()

    assert e1.connexion_closed("fe80::1","fe80::2") == False
    assert e2.connexion_closed("fe80::2","fe80::1") == True

    assert e2.connexion_closed("fe80::1","fe80::2") == False



# the callback function that listen to TCP requests:
def callback(i, payload):
    """a callback function for the NFQUEUE"""
    
    data = payload.get_data()
    data = IPv6(data)
    
    CGApool = EphemeralPool()


    # we might have intercepted packet for addresses
    # that are NOT Ephemeral CGA


    # if this is a SYN packet:
    # - put back the address in deprecated mode
    # - preparre the next address for the preferred state
    
    # a TCP SYN only
    if data[TCP].flags == 2:
        warn("this is a TCP SYN (address %s goes to deprecated state)\n" % data.src)
        CGApool.reportaddress_as_used(data.src)
        if CGApool.is_ephemeral_CGA(data.src):
            CGApool.prepare_next_valid_address()

    
    

    # first idea: if this is a FIN + ACK (17) packet, remove the address for the interface
    # second idea: if there is one FIN on each side, wait a bit and remove the address 
    # (we implemen the second idea)
    elif data[TCP].flags & 1:

        warn("this is a TCP FIN (addresses %s-%s)\n" % (data.src, data.dst))

        if EphemeralAddress.connexion_closed(data.src, data.dst):
            if CGApool.is_ephemeral_CGA(data.src):
                warn("address %s scheduled to be removed from the interface\n"\
                        % data.src)
                CGApool.schedule_address_removal( data.src )

            elif CGApool.is_ephemeral_CGA(data.dst):
                warn("address %s scheduled to be removed from the interface\n"\
                        % data.src)
                CGApool.schedule_address_removal( data.dst )
    
    payload.set_verdict(nfqueue.NF_ACCEPT)
    
    return 1


class EphemeralAddress(Plugin):
    """implements the idea of ephemeral CGA addresses
    Consists in the following elements:
     - a pool of address (self-regenerated when not enough address are available)
     - a mechanism that deprecates/un-deprecates address when they should be selected for outgoing packets
    """


    capabilities = [ "NFQueue", "PERSISTENT_OBJ", 
                     "Address", "Filtering" ]
                     

    
    name="EphemeralAddress"
    QUEUE_NUM = "5"
    TIMEOUT = 60

    # size of the pool of address
    POOL_SIZE = 150
    # could be modified later on
    # PREFIX = "2001:6f8:147b::"
    # PREFIX = "2001:db8:ffff:0::"
    # PREFIX = "2003::"
    # PREFIX = "2001:6f8:202:249::"
    PREFIX = "2001:AAAA:BBBB::"
    INTERFACE = "eth0"

    # represents the half closed connexions 
    # (shared among instances)
    half_conn = []


    @classmethod
    def set_filter_interface(cls, interface, negate=False):
        """set filter on the interfaces"""

        # in FIN packets
        if negate:
            p = Popen ( [ IPTABLES, "-A", "INPUT", "!", "-i",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ],
                    stdout=PIPE, stderr=PIPE )
        else:
            p = Popen ( [ IPTABLES, "-A", "INPUT", "-i",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ],
                    stdout=PIPE, stderr=PIPE )
        output = p.stdout.read() + p.stderr.read()

        # out SYN packets
        if negate:
            p = Popen ( [ IPTABLES, "-A", "OUTPUT", "!", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        else:
            p = Popen ( [ IPTABLES, "-A", "OUTPUT", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        output = output + p.stdout.read() + p.stderr.read()

        # out FIN packets
        if negate:
            p = Popen ( [ IPTABLES, "-A", "OUTPUT", "!", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        else:
            p = Popen ( [ IPTABLES, "-A", "OUTPUT", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        output = output + p.stdout.read() + p.stderr.read()
        return output

    @classmethod
    def unset_filter_interface(cls, interface, negate=False):
        """unset filter on the interfaces"""

        # in FIN packets
        if negate:
            p = Popen ( [ IPTABLES, "-D", "INPUT", "!", "-i",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ],
                    stdout=PIPE, stderr=PIPE )
        else:
            p = Popen ( [ IPTABLES, "-D", "INPUT", "-i",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ],
                    stdout=PIPE, stderr=PIPE )
        output = p.stdout.read() + p.stderr.read()

        # out SYN packets
        if negate:
            p = Popen ( [ IPTABLES, "-D", "OUTPUT", "!", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        else:
            p = Popen ( [ IPTABLES, "-D", "OUTPUT", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        output = output + p.stdout.read() + p.stderr.read()

        # out FIN packets
        if negate:
            p = Popen ( [ IPTABLES, "-D", "OUTPUT", "!", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        else:
            p = Popen ( [ IPTABLES, "-D", "OUTPUT", "-o",
                    interface, "-p", "tcp", "--tcp-flags", "FIN", "FIN",
                    "-j", "NFQUEUE", "--queue-num", cls.QUEUE_NUM ]
                    , stdout=PIPE, stderr=PIPE )
        output = output + p.stdout.read() + p.stderr.read()
        return output
 
    @classmethod
    def get_name(cls):
        """indicates the name of the plugin"""
        return cls.name

    @classmethod
    def listening_queue(cls):
        """queue that listen for outgoing TCP connexions"""
        q = nfqueue.queue()
        q.open()

        q.unbind(AF_INET6)
        q.bind(AF_INET6)


        q.set_callback(callback)

        q.create_queue(5)

        q.set_queue_maxlen(5000)

        return q


    @classmethod
    def init_address(cls, address_obj, extra_param):
        """initialise extra field in an Address obj"""

        if "ephemeral" in extra_param:
            address_obj.ephemeral = extra_param["ephemeral"]
        else:
            address_obj.ephemeral = False

    @classmethod
    def connexion_closed(cls,source, destination):
        """returns a Boolean to indicates 
        if a connexion is closed"""
        cls.half_conn.append((source, destination))

        if (source, destination) in cls.half_conn and\
                (destination, source) in cls.half_conn:
            # do some cleanup
            del cls.half_conn[cls.half_conn.index((source, destination))]
            del cls.half_conn[cls.half_conn.index((destination, source))]

            return True
        else:
            return False
    @classmethod
    def persisent_obj_start(cls):
        """initialize an Ephemeral CGA address pool"""
        EphemeralCGApoolStart()

class EphemeralPool(object):
    """the pool contains two types of Ephemeral CGA:
    - the ones that are currently in use
    - the ones that are free to be used"""

    __shared_object = {}

    def __init__(self):
        """initialize the Ephemeral Address Pool"""

        # DP borg, all instances share the same variables
        self.__dict__ = self.__shared_object
        # DP borg
        if not hasattr(self,"freePool"):
            self.freePool = []
            self.freePoolLock = RLock()
        if not hasattr(self,"inUsePool"):
            self.inUsePool = []
            self.inUsePoolLock = RLock()
        if not hasattr(self,"TBremovedAddr"):
            self.TBremovedAddr = {}
            self.TBremovedAddrLock = RLock()

        # some connxion are required to the Neighbor Cache
        # it seems better to always stay connected
        if not hasattr(self,"nc"):
            self.nc = NeighCache()

        if not hasattr(self,"clean"):
            self.clean = True

    def get_address_in_use(self):
        """returns the addresses that are currently in use"""
        with self.inUsePoolLock:
            return self.inUsePool


    def get_not_yet_used_addresses(self):
        """returns the list of addresses that are currently free to be used"""
        with self.freePoolLock:
            return self.freePool

    def prepare_next_valid_address(self):
        """pick on address from the pool and change it valid state"""
        with nested(self.freePoolLock, self.inUsePoolLock):
            try:
                address = self.freePool[0]
                address.modify() # by default, place the address in "valid" state
                del self.freePool[0]
                self.inUsePool.append(address)
            except IndexError: # or will crash when no address is left
                pass



    def is_ephemeral_CGA(self, address):
        """return True if the address is an Ephemeral CGA"""
        with nested(self.freePoolLock, self.inUsePoolLock):
            return str(address) in [ str(address) for address in self.freePool + self.inUsePool ]

    def reportaddress_as_used(self, address):
        """report the address as an address that is currently in use"""

        # connect to the NC to obtain the list of currently assigned addresses
        configured_addresses = self.nc.dump_addresses()

        # address = None

        # obtain the address object
        for address_obj in ( a for a in configured_addresses
                                        if str(a) == address):
            address = address_obj
            break # we can stop here as the address is only recorded one


        # change the state of the address to deprecated
        try:
            address.modify(preferred_lft=0)
            warn("Address %s reported to have initialized a connexion is now being deprecated\n" % address)
        except AttributeError: # the address does not belong to our program
            pass

        # if this is an ephemeral CGA from the "free" pool, place it
        # in the "in use" pool
        try:
            with nested(self.freePoolLock, self.inUsePoolLock):
                index = self.freePool.index(address)
                del self.freePool[index]
                self.inUsePool.append(address)
        except (ValueError, IndexError):
            pass

    def regenerate(self, n_address):
        """create n_address addresses to fill the pool
        there should be POOL_SIZE addresses in the pool"""
        warn("Ephemeral CGA pool: regeneration of %i addresses\n" % n_address)
        for i in range(n_address):
            a = Address(key=NDprotector.default_publickey,
                    interface = EphemeralAddress.INTERFACE,
                    prefix = EphemeralAddress.PREFIX,
                    ephemeral = True,
                    sec = 0,
                    dad=False) # temporary
            a.modify(preferred_lft=0)
            with self.freePoolLock:
                self.freePool.append(a)

            # connect to the NC to store the new address
            self.nc.store_address(a)
        warn("Ephemeral CGA pool: regeneration of %i addresses complete\n" 
                % n_address)

    def schedule_address_removal(self,address):
        """schedule an address for removal after TIMEOUT seconds"""

        EphemeralAddress.TIMEOUT

        with nested(self.inUsePoolLock, self.TBremovedAddrLock):
            for address in ( a for a in self.inUsePool if str(a) == address ):
                index = self.inUsePool.index(address)
                del self.inUsePool[index]
                self.TBremovedAddr[address] =  EphemeralAddress.TIMEOUT

                break




    def close_cleaning_thread(self):
        """close the cleaning/maintenance thread"""
        self.clean = False





def pool_maintenance():
    """cleansen the pool:
    - remove addresses scheduled to be removed (in the in-use address)
    - regenerate the cache"""

    pool = EphemeralPool()

    with pool.TBremovedAddrLock:
        for (address, ttl) in pool.TBremovedAddr.items():
            if ttl <= 0:
                # suppress the address from the system
                warn("scheduled removal for address %s is now removed\n" % address)
                address.remove()
                pool.nc.del_address(str(address))

                del pool.TBremovedAddr[address]
            else:
                pool.TBremovedAddr[address] = ttl -1

    # regenerate the pool of addresses
    remaining_addresses = 0
    with pool.freePoolLock:
        remaining_addresses = len(pool.freePool)
    if remaining_addresses <= EphemeralAddress.POOL_SIZE/2 :
        pool.regenerate(EphemeralAddress.POOL_SIZE - remaining_addresses)



def EphemeralCGApoolStart():
    """provide access to the pool"""

    # initialisation of the pool
    pool = EphemeralPool()
    # no need to generate a complete pool
    # done in the maintenance thread
    pool.regenerate(EphemeralAddress.POOL_SIZE)
    pool.prepare_next_valid_address()

    # subscribe the cleaning Thread for the pool
    # (be warned that this function will add delay to the main thread)
    #cleanup_thread_subscribe(pool_maintenance)
