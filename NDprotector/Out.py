"""this module processes all the out-going packets by using nfqueue"""
import random
import sys

from NDprotector.Log import warn
from NDprotector.NeighCache import NeighCache
from scapy6send.scapy6 import *
from NDprotector.Tool import used_interfaces
import NDprotector


if "lib" not in sys.path:
    sys.path.append("lib")
import nfqueue


def callback(i,payload):
    """a callback function called on each outgoing packets"""

    data = payload.get_data()

    packet = IPv6(data)

    nc = NeighCache()


    # fetching the latest configured addresses on the interfaces
    configured_addresses = nc.dump_addresses()

    if packet.haslayer(ICMPv6ND_NS) \
       or packet.haslayer(ICMPv6ND_NA):

        for addr in configured_addresses:
            if str(addr) == packet[IPv6].src:
                if packet.haslayer(ICMPv6ND_NS):
                    nonce = "".join([ chr(random.randrange(255))  for i in range(6)])
                    nc.record_nonce_out(packet[IPv6].src,packet[IPv6].dst,nonce)
                else:
                    nonce = nc.pop_nonce_out(packet[IPv6].src,packet[IPv6].dst)
                data = addr.sign(data,nonce=nonce)
                warn("signing a NS or NA message\n")
                payload.set_verdict_modified(nfqueue.NF_ACCEPT,str(data),len(str(data)))
                return 0
        else:
            if NDprotector.mixed_mode:
                warn("letting go one outgoing unsecured packet\n")
                payload.set_verdict(nfqueue.NF_ACCEPT)
                return
            else:
                warn("dropping one unsecured packet\n")
                payload.set_verdict(nfqueue.NF_DROP)
                return 0
    elif packet.haslayer(ICMPv6ND_RS):
        if NDprotector.is_router == False:
            if packet[IPv6].src == "::" :
                payload.set_verdict(nfqueue.NF_ACCEPT)
                return 0
            else:
                # we need to sign the message
                for addr in configured_addresses:
                    if str(addr) == packet[IPv6].src:

                        # we generate a nonce for this request
                        nonce = "".join([ chr(random.randrange(255))  for i in range(6)])
                        nc.record_nonce_out(packet[IPv6].src,packet[IPv6].dst, nonce)

                        warn("signing an outgoing RS message\n")
                        
                        data = addr.sign(data,nonce=nonce)
                        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(data), len(str(data)))
                        return 0
                else:
                    if NDprotector.mixed_mode:
                        warn("letting go one outgoing unsecure RS packet\n")
                        payload.set_verdict(nfqueue.NF_ACCEPT)
                        return 0
                    else:
                        warn("dropping one unsecure RS packet\n")
                        payload.set_verdict(nfqueue.NF_DROP)
                        return 0
        else:
            # a router does not send this kind of messages
            payload.set_verdict(nfqueue.NF_DROP)

    elif packet.haslayer(ICMPv6ND_RA):
        if NDprotector.is_router:
            # we need to sign the message
            for addr in configured_addresses:
                if str(addr) == packet[IPv6].src:
                    nonce = nc.pop_nonce_out(packet[IPv6].src,packet[IPv6].dst)
                    if nonce != None:
                        nonce = nonce.data

                    warn("signing an outgoing RA message\n")
                    
                    # note that if nonce is None, no nonce value will join this message
                    data = addr.sign(data,nonce=nonce)
                    payload.set_verdict_modified(nfqueue.NF_ACCEPT,str(data),len(str(data)))
                    return 0
            else:
                if NDprotector.mixed_mode:
                    warn("letting go one outgoing unsecure RA packet\n")
                    payload.set_verdict(nfqueue.NF_ACCEPT)
                    return 0
                else:
                    warn("dropping one unsecure RA packet\n")
                    payload.set_verdict(nfqueue.NF_DROP)
                    return 0
        else:
           # a host does not send RA messages
           payload.set_verdict(nfqueue.NF_DROP)
           return 0

    else:
        warn("letting a non NDP message go out\n")
        payload.set_verdict(nfqueue.NF_ACCEPT)

    return 0

def out_queue():
    """setup the NF_queue to "rule" the outgoing packets"""

    q = nfqueue.queue()
    q.open()

    # need to be done once
    # performed in In.py
    #q.unbind(AF_INET6)
    #q.bind(AF_INET6)


    q.set_callback(callback)

    q.create_queue(2)


    q.set_queue_maxlen(5000)

    # send a Router Solitication to all neighboring routers
    # (only at the launch of the program)
    if not NDprotector.is_router:
        SendRTSol()

    return q

def SendRTSol():
    """send a simple Router Solicitation message on all the configured interfaces"""

    # get all the interfaces on
    # which we should send a message on
    nc = NeighCache()
    configured_addresses = nc.dump_addresses()
    interfaces = used_interfaces(configured_addresses)

    for iface in interfaces:

        p = Ether(src=get_if_hwaddr(iface)) / \
            IPv6(src = "::",dst = "ff02::2")/ \
            ICMPv6ND_RS()
        sendp(p,iface=iface,verbose=NDprotector.verbose)
        warn("Sending an RS on interface %s\n" % iface)
