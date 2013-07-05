NDprotector: an implementation of CGA & SEND for GNU/Linux based on Scapy6
==========================================================================

Presentation
------------

This page hosts an implementation of CGA & SEND  that works on Linux. It is
part of the [ANR](http://www.agence-nationale-recherche.fr/) founded
[MobiSEND](http://mobisend.org) project.

The Neighbor Discovery protocol ([RFC4861] and [RFC4862]) for IPv6 which is
equivalent to [IPv4 ARP][RFC826], is prone to many different attacks. RFC 3756
describes and categorizes these attacks.  Well aware of this issue, the IETF
developped an extension to the Neighbor Discovery protocol. It is named [Secure
Neighbor Discover (SEND)][RFC3971]. It relies on a new format of IPV6 addresses
described in [RFC3972] named Cryptographically Generated Addresses (CGA).  A
CGA address securely binds a Public Key to an address. SEND further completes
the mechanism and  carries new Neighbor Discovery options (Nonce, RSA
Signature, ...), that allow the node to prove its address ownership (thus
preventing address spoofing) and that the content of the message is unaltered.

The implementation is currently limited to Linux platform due to its dependency
to the [iproute2]
(http://www.linuxfoundation.org/collaborate/workgroups/networking/iproute2),
[ip6tables](http://www.netfilter.org/projects/iptables/index.html) and
[netfiter queue](http://www.netfilter.org/projects/libnetfilter_queue/index.html)
utilities.  However, with changes related to the aforementioned parts, we
believe this implementation could be ported to others platforms (like the *BSDs).

<em>Please note: the implementation in itself is much more a Proof-of-Concept
code than a production-ready software. You should not use it in critical
environments. It is now mostly in maintenance mode: meaning that if you come to
me with a problem and a patch for it, I'll apply it, otherwise I'll try to help
as I can (in the limited free time I have).</em>


How does it work ?
------------------

When a Neighbor Discovery message (i.e. an ICMPv6 packet) is received or is
emitted on/by an interface, a hook set by ip6tables redirect the packet to the
userspace before it goes to the kernel/network card. This extraction is
performed by the libnetfilter_queue. We then use a modified version of scapy6
(Arnaud Ebalard added SEND messages format, CGA generation procedure and X.509
certificate processing to the original scapy6). Scapy6 dissects each
intercepted messages. We inspect each "important" field and decide if we need
to modify the message (add an RSA signature option for outgoing packets) or let
the message pass (for ingoing packet with a correct signature).

Each assigned address is bound to a Public Key/Private Key. Whenever a message
comes from this address, the implementation uses the Private Key and adds an
RSA signature option to it.

Dependencies
------------

This software depends on:

  * [Python](http://python.org) >= 2.5
  * [OpenSSL](http://openssl.org) (ECC suppport in NDprotector version > 0.4 requires at least version 1.0 of OpenSSL)
  * [Ip6tables](http://www.netfilter.org/projects/iptables/index.html)
  * [libnetfilter_queue library](http://www.netfilter.org/projects/libnetfilter_queue/index.html)
  * [Python's libnetfilter_queue bindings](http://software.inl.fr/trac/wiki/nfqueue-bindings) (NDprotector version > 0.3 requires at least version 0.3 of libnetfilter_queue bindings)

All of these can be prepackaged on your distribution. For exemple, on Debian and Ubuntu:

		$ apt-get install openssl iptables \
		     libnetfilter-queue-dev \
		     nfqueue-bindings-python


Optionally, you may want to install:

* OpenSSL with the support of [RFC3779] (see the INSTALL.txt file for details
  on a quick hack to enable this support). On Gentoo, there is a USE flag that
  enable the RFC 3779 support (the name of the flag is *rfc3779*)

A word of caution: some distributions (like OpenSuse 10.2 version) disable IPv6
support when shipping Python. It breaks this program as we are relying on IPv6
features to make everything work.

Changelog
---------

* **0.5**:

	- extended support of the Signature Algorithm Agility (draft-cheneau-csi-cga-pk-agility)
	- improves the code for key format detection (mainly ECC improvements)
	- some bug fixes

* **0.4**:

	- huge change in the code architecture that provides performance boost
	- support of Signature Algorithm Agility (draft-cheneau-csi-send-sig-agility and draft-cheneau-csi-ecc-sig-agility)
	- a tool to generate CGA address for the configuration file (genCGA.py)
	- bug fixes

* **0.3**:

	- better handling of the transitionnal mode (mixing secured nodes with unsecured nodes)
	- addresses assigned through SLAAC (RFC 4862) can now access /deprecated/ state
	- various bug fixes

* **0.2**: Initial version

Limitations
-----------

This software has no direct access to the kernel space. Which is "good" as we
can not crash the kernel. However, it involves that we need to emulate the
behavior of some kernel structure, which is not always feasible.

Later improvements may require to add a CGA address support inside the Linux
kernel (which can benefit to other implementations as well). In practice, we
plan that the CGA parameter data structure could be passed to the kernel so it
could assign CGA addresses to specified interfaces.

Due to a lack of specification in RFC 3971, we do not implement the
Certificate's CRL verification. This is an ongoing work in IETF's [CGA and SEND
maIntenance](http://tools.ietf.org/wg/csi/) working group. It will be
integrated in this implementation as soon as a valid proposal emerges.

Licencing
---------

The project uses [scapy](http://www.secdev.org/projects/scapy/) extensions that were developped by Arnaud Ebalard. Scapy is licenced under GPLv2. All other parts of the project are licenced as follow:

<em>
Copyright (c) 2009, Télécom SudParis
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of the Télécom SudParis nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
</em>


Other implementations
---------------------

Some other implementations are also available (please report new implementations you may find, they will be added here):

* [Cisco routers](http://www.cisco.com/en/US/docs/ios/ipv6/configuration/guide/ip6-first_hop_security_ps10591_TSD_Products_Configuration_Guide_Chapter.html)
* [Huawei and BUPT (Beijing University of Post and Telecommunications)](http://code.google.com/p/ipv6-send-cga/) released a C code with modification to the Linux kernel.
* NTT Docomo has [discontinued support of their historical implementation](http://www.docomolabs-usa.com/lab_opensource.html).
* [Easy-SEND](http://sourceforge.net/projects/easy-send/) a Java-based implementation.

Frequently asked questions
--------------------------

If you run into some trouble while trying to have the implementation working, please have a look at the [FAQ.md](FAQ.md) file. I compiled it from the various emails I received.

Contact
-------

You can send me comments at tony.cheneau@amnesiak.org. Please prefix the title
of the email by "[ndprotector]" so I can better process it. Better yet, open an
issue on Github so that yours comments can benefit others.

Contributors
------------

* Arnaud Ebalard contributed the scapy6 extensions for CGA and SEND.

[ARP]: https://tools.ietf.org/html/rfc826
[RFC3779]: https://tools.ietf.org/html/rfc3779
[RFC3971]: https://tools.ietf.org/html/rfc3971
[RFC3972]: https://tools.ietf.org/html/rfc3972
[RFC4861]: https://tools.ietf.org/html/rfc4861
[RFC4862]: https://tools.ietf.org/html/rfc4862
