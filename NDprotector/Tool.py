"""Provides various tools"""
from scapy6send.scapy6 import SigAlg, CGAExt
from scapy6send.scapy import get_if_list
try:
    from scapy6send.ecc import ECCkey
except ImportError:
    class ECCkey:
        def __init__(self, * args):
            print "ECC support disabled, the configuration file should not enable it"
            raise NotImplementedError

from scapy6send.cert import PubKey, Key


def used_interfaces(list_of_address):
    """Returns a set of interfaces that the addresses are configured on"""

    interfaces = set()
    for address in list_of_address:
        interfaces.update([address.get_interface()])

    return interfaces

def test_SigAlgList_compute():

    
    alg_list = [ SigAlg(sign = 1, sigtypeID = 1) ,
                 SigAlg(sign = 1, sigtypeID = 0) ,
                 SigAlg(sigtypeID = 10) ,
                 SigAlg(sigtypeID = 9) ]
    assert SigAlgList_compute(1, [10, 9]) == alg_list

    alg_list = [ SigAlg(sign = 1, sigtypeID = 0) ,
                 SigAlg(sign = 1, sigtypeID = 1) ,
                 SigAlg(sigtypeID = 10) ,
                 SigAlg(sigtypeID = 9) ]
    assert SigAlgList_compute(0, [10, 9]) == alg_list

    alg_list = [ SigAlg(sign = 1, sigtypeID = 10) ,
                 SigAlg(sigtypeID = 9) ]
    assert SigAlgList_compute(10, [9]) == alg_list

def SigAlgList_compute(used_sigalg,avail_sigalgs):
    """compute the Signature Algorithm that are available for an address"""

    sigalgs = [ SigAlg(sign = 1, sigtypeID = used_sigalg) ]

    try:
        del avail_sigalgs[avail_sigalgs.index(used_sigalg)]
    except ValueError:
        pass

    try:
        if used_sigalg == 0: # this is RSA/SHA-1, we can sign with RSA/SHA-256
            sigalgs.append( SigAlg(sign = 1, sigtypeID = 1))
            del avail_sigalgs[avail_sigalgs.index(1)]
        elif used_sigalg == 1: # this is RSA/SHA-256, we can sign with RSA/SHA-1
            sigalgs.append( SigAlg(sign = 1, sigtypeID = 0))
            del avail_sigalgs[avail_sigalgs.index(0)]
    except ValueError:
        pass

    for sigalg in avail_sigalgs:
        sigalgs.append(SigAlg( sigtypeID = sigalg ))

    return sigalgs


def SigAlgList_split(sigalgs):
    """split the Signature Algorithm list in two: the algs that permits signature
    and the ones that can only verify it"""

    sign = []
    verify = []
    for sigalg in sigalgs:
        if sigalg.sign:
            sign.append(sigalg.sigtypeID)
        else:
            verify.append(sigalg.sigtypeID)

    return (sign, verify)


def init_values(obj):
    """initialize internal values of the object"""

    # counts the number of addresses assigned on each interfaces
    obj.currently_used_interfaces = {}

    for iface in get_if_list():
        obj.currently_used_interfaces[iface] = 0 

def test_Address_find():
    """tests the Address_find() function"""

    from NDprotector.Address import Address
    a = Address(prefix="fe80::", sec=0)
    b = Address(prefix="fe80::", sec=0)
    c = Address(prefix="fe80::", sec=0)
    d = Address(prefix="fe80::", sec=0)


    assert c == Address_find([a, b, c], str(c))
    assert None == Address_find([a, b, c], str(d))



def Address_find(list_of_address, address_str):
    """Find an address object among a list of address"""

    for address in list_of_address:
        if str(address) == address_str:
            return address

    return None

def test_load_key():
    """unitary test for load_key and load_pkey"""

    rsa_private_key = file("examples/test/test_key.pem").read()
    rsa_private_key_file = "examples/test/test_key.pem"
    ecc_key = "examples/test/test_key_ecc.pem"
    ecc_key_file = file("examples/test/test_key_ecc.pem").read()

    assert load_key("testvector1234") == "testvector1234"
    assert load_key("testvector1234") == "testvector1234"

    rsa_private_key_obj = load_key(rsa_private_key)
    rsa_private_key_file_obj = load_key(rsa_private_key_file)

    assert str(rsa_private_key_obj) == str(rsa_private_key_file_obj)

    rsa_public_key = str(rsa_private_key_obj.toPubKey())
    assert str(load_pkey(rsa_private_key_file)) == str(load_pkey(rsa_public_key))

    assert str(load_key(ecc_key)) == str(load_key(ecc_key_file))
    assert str(load_pkey(ecc_key)) == str(load_pkey(ecc_key_file))

    assert load_key(rsa_private_key).__class__ == Key
    assert load_pkey(load_key(rsa_private_key)).__class__ == PubKey
    assert load_pkey(rsa_private_key).__class__ == PubKey

def load_key(keypath_or_derkey_or_pemkey, eccsupport=True):
    """load a Private Key, no matter its type
    Return keypath_or_derkey_or_pemkey on failure"""

    # try RSA first, then ECC, if nothing succeed, it returns the original string
    try:
        return Key(keypath_or_derkey_or_pemkey)
    except:
        try:
            if eccsupport:
                return ECCkey(keypath_or_derkey_or_pemkey)
        except:
            pass
        return keypath_or_derkey_or_pemkey


def load_pkey(keypath_or_derkey_or_pemkey, eccsupport=True):
    """load a Public Key, no matter its type
    Return keypath_or_derkey_or_pemkey on failure"""

    try:
        # TODO rewrite the next condition
        if keypath_or_derkey_or_pemkey.__class__ == Key:
            return keypath_or_derkey_or_pemkey.toPubKey()
        else:
            raise "argument is not an object"
    except:
        try:
            return PubKey(keypath_or_derkey_or_pemkey)
        except:
            try:
                return Key(keypath_or_derkey_or_pemkey).toPubKey()
            except:
                try:
                    if eccsupport:
                        return ECCkey(keypath_or_derkey_or_pemkey)
                except:
                    pass
                return keypath_or_derkey_or_pemkey

def test_cga_pds():
    """various test for the CGA PDS extensions conversion routines"""
    
    from scapy6send.ecc import NID_secp256k1

    k1 = ECCkey(NID_secp256k1)
    k2 = ECCkey(NID_secp256k1)
    k3 = ECCkey(NID_secp256k1)

    list_of_public_key = [ k1, k2, k3 ]

    CGAExtList = PubKeyListtoCGAPKExtList(list_of_public_key)

    list_of_public_key2 = CGAPKExtListtoPubKeyList(CGAExtList)

    assert [ str(k) for k in list_of_public_key ] == [ str(k) for k in list_of_public_key2 ]

    CGAExtList.insert(1, CGAExt(etype=0xFFFD, edata="fakeExt"))

    list_of_public_key3 = CGAPKExtListtoPubKeyList(CGAExtList)
    assert [ str(k) for k in list_of_public_key ] == [ str(k) for k in list_of_public_key3 ]



def PubKeyListtoCGAPKExtList(list_of_public_keys):
    """Construct a list of CGA PDS extensions containing the Public Keys in
    parameter"""

    if type(list_of_public_keys) == str:
        list_of_public_keys = [ list_of_public_keys ]

    CGAExtList = []
    for pk in list_of_public_keys:
        # 0xFFFD is an experimental value, as defined in RFC 4581
        strpk = str(load_pkey(pk))
        CGAExtList.append(CGAExt(etype=0xFFFE, edata=strpk))

    return CGAExtList

def CGAPKExtListtoPubKeyList(CGAExtList):
    """Construct a list of Public Key from a list of CGA PDS extensions"""


    list_of_public_keys = []

    # currently, the recongnize Public Key are only of type RSA or ECC
    for ext in CGAExtList:
        if ext.etype == 0xFFFE: # this is a Public Key extension

            list_of_public_keys.append (load_pkey(ext.edata))

    return list_of_public_keys
