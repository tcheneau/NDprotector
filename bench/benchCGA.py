#!/usr/bin/python 
"""this little program only serves one purpose: benchmarking the speed of:
    - CGA generation
    - CGA verification
    - Signature generation
    - Signature verification"""

# import cProfile, sys, pstats
import sys, time

sys.path.append("..")


from scapy6send.ecc import *
from scapy6send.cert import *
from scapy6send.scapy6 import *
from NDprotector.Tool import PubKeyListtoCGAPKExtList

sigtypeID = 9
extrakeynum =3

cga_gen_time = []
cga_verif_time = []
sign_gen_time = []
sign_verif_time = []

def construct_message(address):
    p = str( IPv6(src = address,dst = inet_ntop(socket.AF_INET6, # dst is the solicited node multicast address
             in6_getnsma(inet_pton(socket.AF_INET6, address))))/
             ICMPv6ND_NS(tgt = address) /
             ICMPv6NDOptSrcLLAddr(lladdr = "00:11:22:33:44:55"))
    return p

def sign(data, pds, key):
    msg = IPv6(data)
    msg /= ICMPv6NDOptCGA(cgaparams = pds) / \
               ICMPv6NDOptTimestamp() / \
               ICMPv6NDOptNonce() 

    extra_payload_len = len(str(msg.getlayer(ICMPv6NDOptCGA)))
    msg[IPv6].plen += extra_payload_len

    # dirty hack: force to recompute the (ICMP) checksum
    del(msg[IPv6].payload.cksum)

    # freezing data inside the new option fields
    msg = IPv6(str(msg))


    keyh = get_public_key_hash(key, sigtypeID=sigtypeID)

    # adding the signature
    msg /= ICMPv6NDOptUSSig(key=key, pos = 0,
            keyh = keyh, sigtypeID=sigtypeID)
    


    # dirty hack: force the update of the payload length
    extra_payload_len = len(str(msg.getlayer(ICMPv6NDOptUSSig)))
    msg[IPv6].plen += extra_payload_len


    # dirty hack: force to recompute the (ICMP) checksum (once again)
    del(msg[IPv6].payload.cksum)


    return str(msg)

def cga_verify(address, data):
    return CGAverify(address, IPv6(data).getlayer(CGAParams))

def signature_verify(data,k):
    return IPv6(data)[ICMPv6NDOptUSSig].verify_sig(k)

def compute_key():
    return ECCkey(NID_secp256k1)

def gen_cga(key):
    return CGAgen("fe80::", key, 1,
            ext = PubKeyListtoCGAPKExtList([ key for i in range(extrakeynum)]) )

def bench_single_ecc():
    for i in range(10000):
        k = compute_key()
        # computes a CGA address
        before = time.time()
        (address, params) = gen_cga(k)
        after = time.time()

        cga_gen_time.append(after - before)

        m = construct_message(address)
        before = time.time()
        m = sign(m, params, k)
        after = time.time()
        sign_gen_time.append(after - before)
        

        before = time.time()
        cga_verify(address, m)
        after = time.time()
        cga_verif_time.append(after - before)

        before = time.time()
        signature_verify(m, k)
        after = time.time()
        sign_verif_time.append(after - before)


        print "loop #%d computed, message size: %d" % (i, len(m))


if __name__ == "__main__":

    try:
        extrakeynum = int(sys.argv[1])
    except (IndexError, ValueError):
        print "first argument should be the number of Public Key stored in the Public Key Extensions"
        sys.exit(-1)
    bench_single_ecc()

    f = open("%d-key-ecc-duration" % extrakeynum, "w")

    f.write("cga_gen_time = " + repr(cga_gen_time) + "\n")
    f.write("cga_verif_time = " + repr(cga_verif_time) + "\n")
    f.write("sign_gen_time = " + repr(sign_gen_time) + "\n")
    f.write("sign_verif_time = " + repr(sign_verif_time) + "\n")

    f.close()

    print "mean CGA generation time: " + str(sum(cga_gen_time) / len(cga_gen_time))
    print "mean CGA verification time: " + str(sum(cga_verif_time) / len(cga_verif_time))
    print "mean Signature generation time: " + str(sum(sign_gen_time) / len(sign_gen_time))
    print "mean Signature verification time: " + str(sum(sign_verif_time) / len(sign_verif_time))
    # prof = cProfile.run("bench_single_ecc()","%d-key-ecc.prof" % extrakeynum)


    # print """############## Single ECC Public Key ###############"""
    # stats = pstats.Stats("%d-key-ecc.prof" % extrakeynum)
    # stats.strip_dirs()
    # stats.sort_stats('name')
    # stats.print_stats('benchCGA.py:')


