from setuptools import setup
from glob import glob

setup(
    name = "ndprotector",
    version = "0.5",
    author = "Tony Cheneau",
    author_email = "tony.cheneau@it-sudparis.eu",
    description = "Yet another userspace implementation of CGA (RFC 3972) and \
    SEND (RFC 3971)",
    licence = "BSD",
    keywords = "cga send",
    
    packages = [ 'NDprotector', 'NDprotector/plugins', 'scapy6send' ],
    scripts = [ 'ndprotector.py', 'genCGA.py'],

    data_files = [ ('share/doc/ndprotector/examples',
                    glob('examples/*.conf*') ) ,
                    ('share/doc/ndprotector/doc',
                    glob('doc/*.*') ),
                   ( 'share/doc/ndprotector', 
                       [ 'TODO.txt',
                         'INSTALL.txt',
                         'INTEROP.txt',
                         'LICENCE.txt'] ) ],

)

