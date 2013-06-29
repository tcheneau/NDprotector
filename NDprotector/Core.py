import os
import sys

import NDprotector
from NDprotector.Log import *


# default prefix of the configurations file
CONFIG_PREFIX = '/etc/NDprotector'

# default location of the main config file
NDprotector.CONFIG_FILE = os.path.join(CONFIG_PREFIX,'sendd.conf')



def main():
    from NDprotector.ParseOpt import parseoptions
    from NDprotector.Config import readconfig
    from NDprotector.Cleanup import final_cleanup, cleanup_thread_start
    from NDprotector.Filtering import set_filtering_rules
    from NDprotector.NeighCache import NeighborCacheStart
    from NDprotector.CertCache import CertCacheStart
    from NDprotector.Plugin import get_plugins_by_capability
    from NDprotector.NFQueues import run_queues
    from NDprotector.Tool import init_values

    # reading the CLI options
    if len(sys.argv) > 1:
        options = parseoptions(sys.argv[1:])
        if hasattr(options,"verbose"):
            if options.verbose:
                enable_verbose()
            warn("Verbose output enabled\n")
        if options.filename:
            NDprotector.CONFIG_FILE= options.filename

    # loading the configuration file
    warn("Reading configuration file %s\n" % NDprotector.CONFIG_FILE)
    if not os.path.isfile(NDprotector.CONFIG_FILE) or not os.access(NDprotector.CONFIG_FILE,os.R_OK):
        print "%s is not a file or could not be open" % NDprotector.CONFIG_FILE 
        sys.exit(-1)

    # initialize some defaults internal values
    init_values(NDprotector)

    readconfig(NDprotector.CONFIG_FILE)

    if NDprotector.verbose:
        import  cgitb
        cgitb.enable(format="text")

    # set specific filtering rules with ip6tables "protected" interfaces
    set_filtering_rules(NDprotector.configured_addresses) 


    # do the real stuffs

    # starting populating the neighbor cache
    warn("Neighbor Cache initialized\n")
    NeighborCacheStart()

    # starting populating the certificate cache on hosts
    if NDprotector.is_router == False:
        warn("Certification Cache starting\n")
        CertCacheStart()

    plugins = get_plugins_by_capability("PERSISTENT_OBJ")

    for plugin in plugins:
        warn("initiating persistent object for" + plugin.get_name()+ "\n")
        plugin.persisent_obj_start()

    # this thread does the cleanup for all data structure
    # that need regular cleaning (e.g. Neighbor Cache)
    clean_thread = cleanup_thread_start()

    try:
        run_queues()
    except KeyboardInterrupt, message:
        print "\n**Trying to exit gracefully**"
    finally: 
        # should stop every thread, remove addresses, unset filtering
        final_cleanup([clean_thread])



