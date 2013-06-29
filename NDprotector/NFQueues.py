"""handle all the differents Queue that are used by the program"""

from select import select
import sys

from NDprotector.In import in_queue
from NDprotector.Out import out_queue
from NDprotector.CertPath import cpscpa_queue
from NDprotector.Log import warn
from NDprotector.Plugin import get_plugins_by_capability


if "lib" not in sys.path:
    sys.path.append("lib")
import nfqueue

def run_queues():
    """run the different queues and dispatch
    packets for the different callback functions"""

    in_q = in_queue() 
    out_q = out_queue() 
    cpscpa_q = cpscpa_queue()

    plugins = get_plugins_by_capability("NFQueue")

    plugin_queues = [ plugin.listening_queue() \
            for plugin in plugins ]

    # associate a file descritor to its corresponding queue
    queues = {}
    for q in [in_q, out_q, cpscpa_q] + plugin_queues:
        q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        queues[q.get_fd()] = q

    warn("running In/Out/CPSCPA NFQueues\n")
    # TC 04/15/10: took me a while to figure out I could use nfqueues this way
    try:
        while True:
            # warn("waiting for new (intercepted) messages\n")
            (r,w,o) = select(queues.keys(),[],[])

            for filedesc in r:
                queues[filedesc].process_pending(1)

    except KeyboardInterrupt, e:
        print "stopping all the queues"
