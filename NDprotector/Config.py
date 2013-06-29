"""load the main configuration file"""
import NDprotector
from NDprotector.Plugin import init_plugin_path,\
                load_plugins, \
                find_plugins
from NDprotector.Log import warn


def readconfig(config_file):
    """read the config file, check the different option, and return them to the main program"""

    NDprotector.ECCsupport = False
    try:
        from scapy6send.ecc import ECCkey, NID_secp256k1,\
                NID_secp384r1, NID_secp521r1
    except ImportError:
        warn("unable to import ECC library\n")
        warn("ECC support is disabled\n")
    else:
        warn("ECC support is available\n")
        NDprotector.ECCsupport = True


    # load the config file
    execfile(config_file)

    # TODO
    # - sanity checks

    # load the various plugins
    init_plugin_path(NDprotector.pluginpath)

    load_plugins(NDprotector.plugins)

    warn("available plugins: " + repr(find_plugins()) + "\n")
