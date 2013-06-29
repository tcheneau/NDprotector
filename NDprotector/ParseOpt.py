import os, sys
from optparse import OptionParser

def  parseoptions(args):

    parser = OptionParser()

    parser.add_option("-c","--config-file",dest="filename",help="location of the NDprotector config file",metavar="FILE") 
    parser.add_option("-v","--verbose",action="store_true",dest="verbose", default=False, help="print additionnal debug messages")

    options, args = parser.parse_args(args)

    if len(args) != 0:
        print "too much arguments given"
        print parser.print_help()
        sys.exit(-1)

    return options
