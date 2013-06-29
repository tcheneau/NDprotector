"""this module installs/deinstalls ip6tables filtering rule on the interfaces"""
from subprocess import Popen,PIPE
from NDprotector.Log import *
from NDprotector.Tool import used_interfaces

from NDprotector.Plugin import get_plugins_by_capability


IPTABLES = "/sbin/ip6tables"

icmp_type = map(str,range(133,138))

def test_binaries():
    assert os.path.isfile(IPTABLES)

class FilteringException(Exception):
    """thrown when a filtering rule can not apply"""

def iptables_set(chain, interface, type, queuenum, negate=False):
    """set an iptables filtering rule
    "negate" specifies if the interface should be negated"""
    if chain == "INPUT":
        int_flag = "-i"
    elif chain == "OUTPUT":
        int_flag = "-o"
    else:
        raise FilteringException("internal error")

    if negate:
        p = Popen ( [ IPTABLES, "-A", chain, "!", int_flag,
                interface, "-p", "icmpv6", "-j", "NFQUEUE",
                "--icmpv6-type", type,
                "--queue-num", queuenum ], stdout=PIPE, stderr=PIPE )
    else:
        p = Popen ( [ IPTABLES, "-A", chain, int_flag,
                interface, "-p", "icmpv6", "-j", "NFQUEUE",
                "--icmpv6-type", type,
                "--queue-num", queuenum ], stdout=PIPE, stderr=PIPE )
    output = p.stdout.read() + p.stderr.read()
    return output

def iptables_unset(chain, interface, type, queuenum, negate=False):
    """unset an iptables filtering rule
    "negate" specifies if the interface should be negated"""
    if chain == "INPUT":
        int_flag = "-i"
    elif chain == "OUTPUT":
        int_flag = "-o"
    else:
        raise FilteringException("internal error")

    if negate:
        p = Popen ( [ IPTABLES, "-D", chain, "!", int_flag,
                interface, "-p", "icmpv6", "-j", "NFQUEUE",
                "--icmpv6-type", type,
                "--queue-num", queuenum ], stdout=PIPE, stderr=PIPE )
    else:
        p = Popen ( [ IPTABLES, "-D", chain, int_flag,
                interface, "-p", "icmpv6", "-j", "NFQUEUE",
                "--icmpv6-type", type,
                "--queue-num", queuenum ], stdout=PIPE, stderr=PIPE )
    output = p.stdout.read() + p.stderr.read()
    return output

def set_filtering_rules(addresses):
    """add the different filtering rules on the interfaces"""

    plugins = get_plugins_by_capability("Filtering")

    warn("setting filtering rules\n")
    if NDprotector.mixed_mode:
        interfaces = used_interfaces(addresses)


        for interface in interfaces:
            for type in icmp_type:
                output = iptables_set("INPUT", interface, type, "1")
                if output:
                    raise FilteringException("unable to set INPUT filtering rule on %s" % interface)

                output = iptables_set("OUTPUT", interface, type, "2")
                if output:
                    raise FilteringException("unable to set OUTPUT filtering rule on %s" % interface)

            if NDprotector.is_router:
                # type 148 is a CPS message
                output = iptables_set("INPUT", interface, "148", "3")
                if output:
                    raise FilteringException("unable to set CPS filtering rule on %s" % interface)
            else:
                # type 149 is a CPA message
                output = iptables_set("INPUT", interface, "149", "3")
                if output:
                    raise FilteringException("unable to set CPA filtering rule on %s" % interface)

            for plugin in plugins:
                plugin().set_filter_interface(interface)



    else:
        # we only allow SEND protected addresses on this node
        for type in icmp_type:
            output = iptables_set("INPUT", "lo", type, "1", negate = True)
            if output:
                raise FilteringException("unable to set INPUT filtering rule on the node")
            output = iptables_set("OUTPUT", "lo", type, "2", negate = True)
            if output:
                raise FilteringException("unable to set OUTPUT filtering rule on the node")

        if NDprotector.is_router:
            # 148 = CPS
            output = iptables_set("INPUT", "lo", "148", "3", negate = True)
            if output:
                raise FilteringException("unable to set CPS filtering rule on the node")
        else:
            # 149 = CPA
            output = iptables_set("INPUT", "lo", "149", "3", negate = True)
            if output:
                raise FilteringException("unable to set CPA filtering rule on the node")

        for plugin in plugins:
            plugin.set_filter_interface("lo", negate="True")

def unset_filtering_rules(addresses):
    """remove the different filtering rules on the interfaces"""

    plugins = get_plugins_by_capability("Filtering")

    warn("unsetting filtering rules\n")
    if NDprotector.mixed_mode:

        interfaces = used_interfaces(addresses)

        for type in icmp_type:
            for interface in interfaces:
                output = iptables_unset("INPUT", interface, type, "1")
                if output:
                    raise FilteringException("unable to unset INPUT filtering rule on %s" % interface)

                output = iptables_unset("OUTPUT", interface, type, "2")
                if output:
                    raise FilteringException("unable to unset OUTPUT filtering rule on %s" % interface)

        for interface in interfaces:
            if NDprotector.is_router:
                # 148 is a CPS message
                output = iptables_unset("INPUT", interface, "148", "3")
                if output:
                    raise FilteringException("unable to unset CPS filtering rule on %s" % interface)
            else:
                # 149 is a CPA message
                output = iptables_unset("INPUT", interface, "149", "3")
                if output:
                    raise FilteringException("unable to unset CPA filtering rule on %s" % interface)


            for plugin in plugins:
                plugin().unset_filter_interface(interface)



    else:
        for type in icmp_type:
            # we only allow SEND protected addresses on this node
            output = iptables_unset("INPUT", "lo", type, "1", negate= True)
            if output:
                raise FilteringException("unable to unset INPUT filtering rule on the node")

            output = iptables_unset("OUTPUT", "lo", type, "2", negate= True)
            if output:
                raise FilteringException("unable to unset OUTPUT filtering rule on the node")

        if NDprotector.is_router:
            output = iptables_unset("INPUT", "lo", "148", "3", negate= True)
            if output:
                raise FilteringException("unable to unset CPS filtering rule on the node")
        else:
            output = iptables_unset("INPUT", "lo", "149", "3", negate= True)
            if output:
                raise FilteringException("unable to unset CPA filtering rule on the node")

        for plugin in plugins:
            plugin().unset_filter_interface("lo", negate= True)
