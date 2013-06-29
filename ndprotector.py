#!/usr/bin/python2.6
# author: Tony Cheneau <tony.cheneau@it-sudparis.eu>

'''This program protects incomimg and outgoing NDP packets with the SEND
protection as described in RFC 3971 and RFC 3972. RFC3756 identifies the
threats this program addresses.'''



# not the cleanest thing to do, but scapy uses a lot of deprecated code
import warnings
warnings.filterwarnings("ignore",category=DeprecationWarning)

from NDprotector.Core import main

if __name__ == "__main__":

    # uncomment this two lines and comment the next line
    # for profiling the application
    # import cProfile
    # cProfile.runctx("main()", globals(), locals(), "profile.prof")


    main()

