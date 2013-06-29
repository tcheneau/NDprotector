#!/bin/env python
"""a small tool to generate configuration file for CGA addresses"""

import warnings
import sys
from optparse import OptionParser

with warnings.catch_warnings():
    warnings.filterwarnings("ignore",category=DeprecationWarning)
    from NDprotector.Address import Address
    from scapy6send.scapy6 import SigTypeID
    import NDprotector

NDprotector.assign_addresses = False
NDprotector.default_sec_value = 1
NDprotector.default_publickey = None
NDprotector.rsa_key_size =  1024
NDprotector.retrans_timer =  1
NDprotector.SignatureAlgorithms = SigTypeID.keys()

try:
    from scapy6send.ecc import ECCkey
    NDprotector.ECCsupport = True
except ImportError:
    NDprotector.ECCsupport = False

if __name__ == "__main__":
    parser = OptionParser()

    parser.add_option("-i", "--interface", 
            dest="interface", default='eth0',
            help="interface on which the address will be assigned (opt.)")
    parser.add_option("-a", "--address",
            dest="address", default=None,
            help="set the address (when the address is set, you have to provide the Modifier")
    parser.add_option("-p", "--prefix",
            dest="prefix", action="store", type="string", default = None,
            help="set the prefix")
    parser.add_option("-k", "--key",
            dest="key", metavar="FILE", default=None,
            help="set the Public Key (in PEM format)")
    parser.add_option("-m", "--modifier",
            dest="modifier", action="store", type="long", default = None,
            help="set the prefix")
    parser.add_option("-s", "--sec",
            dest="sec", action="store", type="int", default=None,
            help="SEC value (opt.)")
    parser.add_option("-c", "--collcount",
            dest="collcount", action="store", type="int", default=0,
            help="set the collcount value")
    parser.add_option("-e", "--ext",
            dest="extensions", action="store", type="string", default="[]",
            help="set the CGA PDS extensions")
    parser.add_option("-d", "--dad",
            dest = "do_dad", action="store_true", default= False,
            help="perform a Duplicate Address Detection on the newly build address")
            


    opt, args = parser.parse_args(sys.argv[1:])

    if len(args) != 0:
        print "too much arguments given"
        print parser.print_help()
        sys.exit(-1)

    # parse the extensions
    exec ( "extensions =" +  opt.extensions )
 
    NDprotector.assign_addresses = opt.do_dad
    addr = Address(prefix = opt.prefix,
                   address = opt.address,
                   modifier = opt.modifier,
                   sec = opt.sec,
                   collcount = opt.collcount,
                   key = opt.key,
                   ext = extensions, 
                   dad = opt.do_dad,
                   interface = opt.interface)
           

    print addr.config_dump()
    if opt.do_dad:
        addr.remove()
