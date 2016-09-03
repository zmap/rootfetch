Root Fetch
==========

Root Fetch is a set of python scripts for programmatically retrieving the 
root stores from common products. We currently support:

  - Apple
  - Mozilla NSS
  - Microsoft
  - Java
  - Google CT Servers

Requirements
------------

rootfetch is primarily just a wrapper around other tools, but with a common 
interface. As such, it has an eclectic set of requirements.

Microsoft:

 - Install cabextract (e.g., `sudo apt-get install cabextract`)
 - Install perl and following CPAN modules: Convert::ASN1, JSON, DateTime (e.g., `sudo cpan Convert::ASN1`)

Mozilla:

 - Install extract-nss-root-certs to $PATH. Linux and Mac OS versions are included but not installed

Apple:

 - Install Beautiful Soup (`sudo python setup.py develop`)

