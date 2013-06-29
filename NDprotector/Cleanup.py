"""Clean all object when exiting in a specific order"""
from signal import SIGINT, signal, SIG_IGN
from threading import Thread
from time import sleep

import NDprotector
from NDprotector.Filtering import unset_filtering_rules
import NDprotector.NeighCache


NDprotector.cleaning_functions = []

def cleanup_thread_start():
    """starts a cleanup thread"""

    # when set to false, the thread stops
    NDprotector.cleanup = True

    clean_thread = Thread(target=cleanup_thread)
    clean_thread.start()

    return clean_thread

def cleanup_thread():
    """a thread that calls various cleaning functions"""
    while NDprotector.cleanup:
        sleep(1)

        # actual cleaning here based on the subscribers
        for f in NDprotector.cleaning_functions:
            f()

def cleanup_thread_stop():
    """stops the cleanup thread"""

    NDprotector.cleanup = False

def cleanup_thread_subscribe(function):
    """subscribe a function to the cleanup thread"""
    NDprotector.cleaning_functions.append(function)

def final_cleanup(thread_list):
    """clean the filtering rules, remove the addresses from the interfaces,
    kill the program to be sure that no running thread remains"""


    # making sure that the cleaning up process
    # will not get interrupted
    signal(SIGINT,SIG_IGN)

    # stopping all running threads
    cleanup_thread_stop()

    for t in thread_list:
        t.join(1)

    neighcache = NDprotector.NeighCache.NeighCache()
    configured_addresses = neighcache.dump_addresses()

    if NDprotector.assign_addresses:
        for addr in configured_addresses:
            addr.remove()

    unset_filtering_rules(configured_addresses)

    # so the other cleaning threads can finish
    # and exit properly
    # sleep(1)

