"""this module processes all the in-going packets by using nfqueue"""
from socket import AF_INET6
import sys

from NDprotector.Log import warn

from NDprotector.Address import Address
from NDprotector.NeighCache import NeighCache
from NDprotector.CertCache import CertCache
from NDprotector.Tool import SigAlgList_split, CGAPKExtListtoPubKeyList
from scapy6send.scapy6 import *
import NDprotector


if "lib" not in sys.path:
    sys.path.append("lib")
import nfqueue

try:
    from scapy6send.ecc import ECCkey
except ImportError:
    pass


def callback(i, payload):
    """a callback function called on each ingoing packets"""


    data = payload.get_data()
    packet = IPv6(data)
    
    # we try to extract the SSAO if available
    try:
        (signalgs, verifalgs) = SigAlgList_split(packet[ICMPv6NDOptSSA].sigalgs)
    except AttributeError:
        signalgs = []
        verifalgs = []

    # may be buggy due to the order of get_if_list()
    # (in that case, we could use the if_nametoindex() )
    interface = get_if_list()[ payload.get_indev() - 1]

    nc = NeighCache()

    if packet.haslayer(ICMPv6ND_NS) \
       or packet.haslayer(ICMPv6ND_NA):

        secured = False
        try:
            address = packet[IPv6].src 
            # we can receive messages from other node performing a DAD
            if address == "::":
                address = packet.tgt
            cga_prop = CGAverify(address,packet.getlayer(CGAParams))
            if not cga_prop:
                warn("an ingoing packet has failed CGA verification test\n")

            else:
                # only perform the RSA signature here,
                # Timestamp and Nonce verification are performed in the NC
                # FIXME: this is not "good", we are subject to a DoS attack here

                list_of_pubkeys = CGAPKExtListtoPubKeyList(packet[CGAParams].ext)
                list_of_pubkeys.insert(0,packet[CGAParams].pubkey)
                pubkey = list_of_pubkeys[packet[ICMPv6NDOptUSSig].pos]
                if isinstance(pubkey, PubKey) and \
                    not (NDprotector.min_RSA_key_size <= pubkey.modulusLen
                        and pubkey.modulusLen <= NDprotector.max_RSA_key_size):
                    warn("A message we received contains"
                         " a Public Key whose size is not allowed\n")
                else: # Public Key is of a correct size 

                    if packet[ICMPv6NDOptUSSig].keyh !=\
                            get_public_key_hash(pubkey, packet[ICMPv6NDOptUSSig].sigtypeID) :
                        warn("Public key contained in the CGA PDS does not match " \
                              "the Public Key hash in the Universal Sig option\n")
                    else:
                        if not packet[ICMPv6NDOptUSSig].verify_sig(pubkey):
                            warn("an ingoing packet has failed Universal Signature verification\n")
                        else:
                            secured = True

        except AttributeError:
            warn("An unsecured packet passed\n")

        
        # if the status is true, we allow the packet to pass
        status = False

        # we can extract the Source Link Layer option from a NS
        if packet.haslayer(ICMPv6ND_NS):
            mac_address = None
            try:
                mac_address = packet.getlayer(ICMPv6NDOptSrcLLAddr).lladdr
            except AttributeError:
                pass


            # the request does not contain
            # any information on L2 address
            if mac_address == None:
                status = True
            else:

                src_address = packet.getlayer(IPv6).src
                if secured:
                    public_key = str(packet.getlayer(CGAParams).pubkey)
                    timestamp = packet.getlayer(ICMPv6NDOptTimestamp).timestamp
                    warn("NC updating an entry with an secured NS message from the address: %s\n" % packet.src)
                    status = nc.update(src_address, mac_address, public_key, timestamp, secured, ssao= (signalgs, verifalgs))
                    if not status:
                        warn("NS Message from %s rejected (due to a bad timestamp or nonce)\n" % packet.src)

                    # record the nonce if any
                    if packet.haslayer(ICMPv6NDOptNonce):
                        nc.record_nonce_in(packet[IPv6].src,packet[IPv6].dst,
                                packet[ICMPv6NDOptNonce].nonce)

                elif NDprotector.mixed_mode == True:
                    warn("NC updating an entry with an unsecured NS message from the address: %s\n" % packet.src)
                    status = nc.update(src_address, mac_address, None, None, secured, ssao= (signalgs, verifalgs))
                else:
                    warn("NC not updating an entry with an unsecured NS message from the address: %s\n" % packet.src)
                    status = False

        # this is a NA, we extract the Target Link Layer option
        else:
            target = packet.tgt


            mac_address = None
            try:
                mac_address = packet.getlayer(ICMPv6NDOptDstLLAddr).lladdr
            except AttributeError:
                pass

            if mac_address == None:
                status = True
            else:


                if secured:

                    public_key = str(packet.getlayer(CGAParams).pubkey)
                    timestamp = packet.getlayer(ICMPv6NDOptTimestamp).timestamp
                    try:
                        nonce = packet.getlayer(ICMPv6NDOptNonce).nonce
                    except AttributeError:
                        nonce = None
                    warn("NC updating an entry with an secured NA message from the address: %s\n" % packet.src)

                    # multicasted messages may not contain any nonce as they are sent spontaneously
                    if packet[IPv6].dst != "ff02::1":
                        status = nc.check_nonce_in(packet[IPv6].src,packet[IPv6].dst,nonce)
                    # only update when the nonce is correct
                    status = status and nc.update(target, mac_address, public_key,\
                                                  timestamp, secured, ssao= (signalgs, verifalgs))
                elif NDprotector.mixed_mode == True:
                    warn("NC updating an entry with an unsecured NA message from the address: %s\n" % packet.src)
                    status = nc.update(target, mac_address, None, None,\
                                       secured, ssao= (signalgs, verifalgs))
                else:
                    warn("NC not updating an entry with an unsecured NA message from the address: %s\n" % packet.src)
                    status = False

    elif packet.haslayer(ICMPv6ND_RA):
        if NDprotector.is_router == True:
            # a router should not receive RA and process them anyway
            status = False
        else:
            status = False
            # check RSA signature, extract PK

            certcache = CertCache()

            # extract the prefix(es) from the RA message
            prefixes = []
            try:
                next_prefix = packet.getlayer(ICMPv6NDOptPrefixInfo)
                while next_prefix:
                    if next_prefix.validlifetime != 0 and next_prefix.prefixlen == 64:
                        prefixes.append(next_prefix.prefix)
                    next_prefix = next_prefix.payload.getlayer(ICMPv6NDOptPrefixInfo)
            except AttributeError:
                pass
            warn("RA contains following prefix(es): %s\n" % `prefixes`)

            if packet.haslayer(ICMPv6NDOptUSSig):
                secured = False

                list_of_pubkeys = CGAPKExtListtoPubKeyList(packet[CGAParams].ext)
                list_of_pubkeys.insert(0,packet[CGAParams].pubkey)
                pubkey = list_of_pubkeys[packet[ICMPv6NDOptUSSig].pos]
                pkhash = get_public_key_hash(pubkey,
                                             packet[ICMPv6NDOptUSSig].sigtypeID)


                if (isinstance(pubkey,PubKey) and \
                   (NDprotector.min_RSA_key_size <= pubkey.modulusLen
                   and pubkey.modulusLen <= NDprotector.max_RSA_key_size))\
                   or\
                   (NDprotector.ECCsupport and isinstance(pubkey, ECCkey)):

                    if CGAverify(packet[IPv6].src,packet.getlayer(CGAParams)) and \
                       packet[ICMPv6NDOptUSSig].keyh ==  pkhash and \
                       packet[ICMPv6NDOptUSSig].verify_sig(pubkey):
                        secured = True
                    else:
                        warn("an ingoing RA has failed CGA verification or Universal Signature test\n")
                else:
                    warn("A message we received contains"
                         " a Public Key whose size is not allowed\n")

                # extract the Link-Layer Address  from the RA message if any
                mac_address = None
                try:
                    mac_address = packet[ICMPv6NDOptSrcLLAddr].lladdr
                except AttributeError:
                    pass

                if secured :
                    keyh = packet[ICMPv6NDOptUSSig].keyh
                    if certcache.trustable_hash(keyh, prefixes,\
                            packet[ICMPv6NDOptUSSig].sigtypeID):
                        warn("Public Key associated to the signature corresponds to a certificate\n")
                    else:
                        # we need to send some CPS in order to recover the certpath
                        secured = False


                        import random

                        warn("Sending a CPS message\n")
                        req_id = random.randrange(1,0xFFFF)
                        certcache.storeid(req_id)
                        p = Ether(src=get_if_hwaddr(interface),dst=mac_address) / \
                            IPv6(src="::", dst=packet[IPv6].src)/ \
                            ICMPv6SEND_CPS(id=req_id,comp=0xffff)
                        sendp(p,iface=interface,verbose=NDprotector.verbose)

                        # we wait for the answers
                        time.sleep(0.4)

                        # we check if the certificate path is now valid
                        secured = certcache.trustable_hash(keyh, prefixes,\
                                packet[ICMPv6NDOptUSSig].sigtypeID)

                # check the nonce if the destination address is not ff02::1
                if secured and not packet[IPv6].dst == "ff02::1" and packet.haslayer(ICMPv6NDOptNonce):
                    nonce = packet.getlayer(ICMPv6NDOptNonce).nonce
                    status = nc.check_nonce_in(packet[IPv6].src,packet[IPv6].dst,nonce)
                elif secured and packet[IPv6].dst == "ff02::1":
                    status = True


                public_key = str(packet.getlayer(CGAParams).pubkey)
                timestamp = packet.getlayer(ICMPv6NDOptTimestamp).timestamp
                
                if status:
                    warn("NC updating an entry with an secured RA message from the address: %s\n" % packet.src)
                    status = nc.update(packet[IPv6].src, mac_address, public_key,\
                                       timestamp,secured, ssao= (signalgs, verifalgs))


                if status:
                
                    
                    configured_addresses = nc.dump_addresses()

                    # Address Autoconfiguration part

                    if NDprotector.assign_addresses:
                        # extract the prefix(es) from the RA message that contains the Autonomous flag
                        prefixes_aut = []
                        try:
                            next_prefix = packet.getlayer(ICMPv6NDOptPrefixInfo)
                            while next_prefix:
                                if next_prefix.prefixlen == 64 \
                                   and next_prefix.A == 1 \
                                   and next_prefix.validlifetime >= next_prefix.preferredlifetime:
                                    

                                    # we update the prefix cache
                                    # (note that the prefix cache will take care
                                    # of prefix whose valid lifetime is now 0)
                                    nc.update_prefix(next_prefix.prefix,
                                                             next_prefix.preferredlifetime,
                                                             next_prefix.validlifetime) 


                                    # we will do autoconfiguration on these addresses
                                    if next_prefix.validlifetime !=0:
                                        prefixes_aut.append((next_prefix.prefix,
                                                             next_prefix.validlifetime,
                                                             next_prefix.preferredlifetime) )

                                    # set the Autonomous flag to 0 so linux kernel won't 
                                    # set a new address too
                                    next_prefix.A = 0

                                next_prefix = next_prefix.payload.getlayer(ICMPv6NDOptPrefixInfo)
                        except AttributeError:
                            pass

                        for (prefix, valid, preferred) in prefixes_aut:
                            for address in configured_addresses:
                                # extract the prefix from the address
                                if address.get_prefix() == prefix:
                                    # we have a correspondance to this address
                                    # refresh the valid and preferred lifetime
                                    address.modify(valid,preferred)
                                    # let the RA message go
                                    break
                            # if no address exists for this prefix
                            else:
                                # create an address for each prefixes
                                new_address =  Address(prefix = prefix, key = NDprotector.default_publickey,
                                                                        sec = 1,
                                                                        interface = interface,
                                                                        autoconf = True,
                                                                        valid = valid,
                                                                        preferred = preferred)
                                warn("created a new address (%s) for prefix %s\n" % (str(new_address), prefix))
                                nc.store_address(new_address)


                        # force checksum calculation
                        del (packet[IPv6].payload.cksum)
                        packet = IPv6(str(packet))
                        
                        # force checksum calculation

                        # TC 02/19/10: for the record,
                        # that was the previous ugly version
                        # dirty hack to copy the message, except the PIO

                        # let the RA message go , but only after the prefix(es) has been removed
                        # (avoid that kernel autoconfiguration process get involved)
                        # eth = Ether(data)

                        # payld = packet
                        # while payld and not isinstance(payld,NoPayload):
                        #     current_layer = payld
                        #     try:
                        #         payld = payld.payload

                        #     except AttributeError:
                        #         payld = None

                        #     try:
                        #         if not isinstance(current_layer,ICMPv6NDOptPrefixInfo):
                        #             current_layer.remove_payload()
                        #             new_eth /= current_layer
                        #     except AttributeError:
                        #         payld = None

                        # TC 03/15/10: previous version included a Ethernet header that does not seem appropriate
                        # new_eth = Ether(src=eth.src, dst=eth.dst) / packet
                        # payload.set_verdict_modified(nfqueue.NF_ACCEPT,str(new_eth),len(str(new_eth)))
                        payload.set_verdict_modified(nfqueue.NF_ACCEPT,str(packet),len(str(packet)))
                        return 0

            elif NDprotector.mixed_mode:
                status = True
            else:
                status = False


    elif packet.haslayer(ICMPv6ND_RS):
        if NDprotector.is_router == True:
            # if the message does not come from the unspecified address,
            # perform normal checks

            if packet[IPv6].src == "::":
            # nothing to do on a message with the unspecified address as 
            # source address
                status = True
            elif packet.haslayer(ICMPv6NDOptUSSig):

                if not (CGAverify(packet[IPv6].src,packet.getlayer(CGAParams)) and \
                   packet[ICMPv6NDOptUSSig].keyh == \
                    get_public_key_hash(packet[CGAParams].pubkey,packet[ICMPv6NDOptUSSig].sigtypeID) and \
                   packet[ICMPv6NDOptUSSig].verify_sig(packet[CGAParams].pubkey)):
                    warn("an ingoing packet has failed CGA verification or USO signature test\n")
                    status = False
                else:

                    # record the nonce if any
                    if packet.haslayer(ICMPv6NDOptNonce):
                        nc.record_nonce_in(packet[IPv6].src,packet[IPv6].dst,
                                packet[ICMPv6NDOptNonce].nonce)

                    src_address = packet[IPv6].src
                    mac_address = None
                    try:
                        mac_address = packet.getlayer(ICMPv6NDOptSrcLLAddr).lladdr
                    except AttributeError:
                        pass

                    public_key = str(packet.getlayer(CGAParams).pubkey)
                    timestamp = packet.getlayer(ICMPv6NDOptTimestamp).timestamp
                    warn("NC updating an entry with an secured RS message from the address: %s\n" % packet.src)
                    status = nc.update(src_address, mac_address, public_key, timestamp, secured = True, ssao= (signalgs, verifalgs))


            elif NDprotector.mixed_mode:
                warn("letting in an unsecured RS message\n")
                status = True
            
            else:
                warn("dropping an unsecured RS message\n")
                status = False
        else:
            # Host do not process RS messages
            status = False

    else:
        warn("letting in a non NDP message\n")
        status = True

    if status:
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else: 
        payload.set_verdict(nfqueue.NF_DROP)
    return 0


def in_queue():
    """setup the NF_queue to "rule" the ingoing packets
    return a NFQueue object"""

    q = nfqueue.queue()
    q.open()

    q.unbind(AF_INET6)
    q.bind(AF_INET6)


    q.set_callback(callback)

    q.create_queue(1)

    q.set_queue_maxlen(5000)

    return q
