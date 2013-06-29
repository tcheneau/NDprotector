"""A nfqueu that listen for CPS/CPA messages"""
from copy import deepcopy
import sys

from NDprotector.Log import warn
from NDprotector.CertCache import CertCache
from NDprotector.NeighCache import NeighCache
from scapy6send.scapy6 import *
import NDprotector


if "lib" not in sys.path:
    sys.path.append("lib")
import nfqueue




def callback(i,payload):
    """a callback function called on each ingoing packets"""

    data = payload.get_data()
    packet = IPv6(data)

    # if something goes wrong and makes this callback crash,
    # the packet is dropped
    payload.set_verdict(nfqueue.NF_DROP)
    

    # receiving interface
    interface = get_if_list()[ payload.get_indev() - 1]

    # extract all the TA option from the CPS/CPA
    list_of_node_trustanchor = []
    ta = packet[ICMPv6NDOptTrustAnchor]
    while ta:
        if ta.nametype == 1:
            # we get the name field of the TA option
            list_of_node_trustanchor.append(ta.name_field)

        ta = ta.payload[ICMPv6NDOptTrustAnchor]


    if NDprotector.is_router:
        # we have a CPS 
        # (filtering rules were set accordingly)

        # CPS's message ID
        req_id = packet[ICMPv6SEND_CPS].id 

        dest_node = packet[IPv6].src
        if dest_node == "::" :
            # if the origin is the unspecified address
            # the answer is on the All-Node multicast address
            dest_node = "ff02::1"

        src_addr = "::"
        if packet[IPv6].dst != "ff02::1" :
            src_addr = packet[IPv6].dst
        else: 
            # lookup for an adress on this interface:
            nc = NeighCache()
            configured_addresses = nc.dump_addresses()
            for address in configured_addresses :
                if address.get_interface() == interface :
                    src_addr = str(address)
                    break



        # send multiple as many Certification Path
        # as there is Trust Anchor options
        for path in deepcopy(NDprotector.certification_path):
            trust_anchor = path[0]

            skip_ta = True

            if list_of_node_trustanchor == []:
                skip_ta = False
            else:
                # check if this trust anchor is trusted by the node
                # if it isn't, we check for the next cert in the path
                while path and skip_ta:
                    trust_anchor = path[0]

                    for ta in list_of_node_trustanchor:
                        # we found the correct trust anchor
                        if ta in str(Cert(trust_anchor)):
                            skip_ta=False
                            break
                    else:
                        try:
                            del path[0]
                        except IndexError:
                            warn("CertPath.py - callback - this is likely to be a bug\n")



            if skip_ta:
                # we do not have a Certification Path
                # down to this Trust Anchor
                continue

            # number of certificates to send
            # (we does not count the TA as we do not send it
            num_components = len(path) - 2

            # send as many CPA as there is certificates in the Certification Path 
            for cert in path[1:]:
                c = Cert(cert) 
                
                warn("sending a CPA message\n")
                p = Ether(src=get_if_hwaddr(interface)) / \
                    IPv6(src=src_addr,dst=dest_node)/ \
                    ICMPv6SEND_CPA(id=req_id,comp=num_components,allcomp=len(path) -1)/ \
                    ICMPv6NDOptCertificate(cert=str(c))
                sendp(p,iface=interface,verbose=NDprotector.verbose)

                num_components -= 1
            

    else: # we have a CPA

        # connect to the Certificate Cache for future decisions
        certcache = CertCache()

        warn("Receiving a CPA message\n")

        req_id = packet[ICMPv6SEND_CPA].id

        # we only accept CPA if they are destined to all the nodes or 
        # if they are destined to our node
        if (packet[IPv6].dst == "ff02::1" and req_id ==0 ) or certcache.id_match(req_id):

            lastCPA = (packet[ICMPv6SEND_CPA].comp == 0)

            # extract all the certificates and feed them to the cache
            certopt = packet[ICMPv6NDOptCertificate]
            while certopt:
                cert = certopt.cert
                cert = cert.output("PEM")
                certcache.storecert(req_id,cert)

                certopt = certopt.payload[ICMPv6NDOptCertificate]

            # when this is the last CPA message, we ask for the 
            # certificate path validation process 
            if lastCPA:
                certcache.checkcertpath(req_id)

    # regardless the content, we drop them
    # the kernel can not parse them anyway...
    # already done at the beginning of the callback
    # payload.set_verdict(nfqueue.NF_DROP)

def cpscpa_queue():
    """setup the NF_queue to "rule" the CPS/CPA messages
    return the NFQueue object"""

    q = nfqueue.queue()
    q.open()

    # need to be done once
    # performed in In.py
    #q.unbind(AF_INET6)
    #q.bind(AF_INET6)


    q.set_callback(callback)

    # queue for the Certificate Path Validation messages is #3
    q.create_queue(3)

    q.set_queue_maxlen(5000)

    return q
