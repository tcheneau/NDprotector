import NDprotector, sys
# by default, verbose printing messages are disabled
NDprotector.verbose = False

def enable_verbose():
    NDprotector.verbose=True
def disable_verbose():
    NDprotector.verbose=False
def warn(str):
    """print a warning message if the verbose mode has been enabled"""
    if NDprotector.verbose:
        print >>sys.stderr, str,
    return
