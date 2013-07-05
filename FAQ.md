List of frequently asked questions
==================================

Installer related issues
------------------------

### Setuptools are not installed

If you obtain the following error when trying to install NDprotector:

	# python setup.py install
	>> Traceback (most recent call last):
	>>  File "setup.py", line 1, in <module>
	>>   from setuptools import setup
	>> ImportError: No module named setuptools


Most likely, you need to install a "setuptools" package on your distro (or
"python-setuptools" on Debian).

Some Neighbor Discovery message does not seem to be protected by SEND
---------------------------------------------------------------------

This can happen some addresses are allocated on the network interfaces prior
to starting NDprotector. This can be solved by "flushing" the interfaces.

For examples, if you want to flush all addresses on eth0, you can do the
following:

		# ip -6 addr flush dev eth0

(Note that the "ip" command is part of the iproute2 package)

Generating a CGA address takes forever
--------------------------------------

Maybe you invoked genCGA.py with a high SEC value. SEC=0 is instantaneous,
while SEC=! is under a second. SEC=2 is about one hour (depending on how fast
is your system).

How to generate a RSA key for the host
--------------------------------------

Using OpenSSL:

		# openssl genrsa 1024 > /etc/NDprotector/key.pem


OpenSSL does not have the RFC 3779 extension, how do I build it ?
-----------------------------------------------------------------

In the OpenSSL source directory:

		# ./config enable-rfc3779


Strange warning about M2crypto not being found
----------------------------------------------

It could happen that you have the following warning message:

		M2Crypt not found, ECC library disabled


You can discard the M2Crypt reference. It indicates that the [M2Crypto]
(http://chandlerproject.org/bin/view/Projects/MeTooCrypto) and thus the
Elliptic Curve support (which corresponds to an experimental extension of mine
of the RFC3971/RFC3972). So, if you are planning to use RSA, it is not a
problem.

I have a question that is not addressed in this FAQ, what should I do
---------------------------------------------------------------------

Just shoot me an email, with "[ndprotector]" in the title, and I'll try to
answer you, and add your question to the FAQ.


Miscellaneous
-------------

* The name of the argument NDprotector.default_publickey is rather misleading.
  It should be a public/private key of the node stored in the PEM format. 
