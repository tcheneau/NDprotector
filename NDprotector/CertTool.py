"""provides extra tools for Certificate that are not provided by scapy6send's Cert.py module"""

def test_extractX501NameFromCert():

    cert_raw = file("examples/test/cacert.pem").read()

    cert = Cert(cert_raw)
    
    name = extractX501NameFromCert(cert.output())

    # check that the DER encoded X501 name is indeed 
    # in the X.509 DER encoded certificate
    assert name in cert.output()

def extractX501NameFromCert(der_formated_cert):
    "extract a DER encoded X501 Name from a X509 certificate"

    try:
        from pyasn1.codec.der import decoder, encoder

        (decoded, undecoded) = decoder.decode(der_formated_cert)
        
        return encoder.encode(decoded.getComponentByPosition(0).getComponentByPosition(3))
    except:
        pass
    return None
