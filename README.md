# mirth-nagios

This project is an implementation of a 'command' that can
be called by Nagios to pull statistics on your 
[Mirth Connect 3.2+](https://www.mirth.com/)
via SNMP.

This project is pretty tightly coupled with the [mirth-snmp](https://github.com/j0hnds/mirth-snmp)
project. The mirth-snmp project provides the SNMP sub-agent
that actually handles the data collection from Mirth Connect.

## Installation

The guts of this project is a single Python script, which should be
placed in the appropriate location on your Nagios server. In our
case that would be the following directory:

    /usr/lib64/nagios/plugins/third-party

## Usage

There's no point in recreating the built-in help for the script. Just
do the following to see the help message:

    $ /usr/lib64/nagios/plugins/third-party/check_mirth.py --help

    usage: check_mirth.py [-h] [-a AUTHPROTOCOL] [-A AUTHPASSWORD] [-C COMMUNITY]
                          [-l SECLEVEL] [-p PORT] [--lcca-critical LCCA_CRITICAL]
                          [--lcca-warning LCCA_WARNING] [-t TIMEOUT] [-u SECNAME]
                          [-v VERSION] [-V]
                          [--signature-critical SIGNATURE_CRITICAL]
                          [--signature-warning SIGNATURE_WARNING]
                          [-x PRIVPROTOCOL] [-X PRIVPASSWORD]
                          hostname

    positional arguments:
      hostname              Specify the host name of the SNMP agent.

    optional arguments:
      -h, --help            show this help message and exit
      -a AUTHPROTOCOL       Set the default authentication protocol for SNMPv3
                            (MD5 or SHA).
      -A AUTHPASSWORD       Set the SNMPv3 authentication protocol password.
      -C COMMUNITY, --community COMMUNITY
                            SNMP Community String to use.(Default: public)
      -l SECLEVEL           Set the SNMPv3 security level,
                            (noAuthNoPriv|authNoPriv|authPriv) (Default:
                            noAuthNoPriv)
      -p PORT, --port PORT  Set the SNMP port to be connected to (Default:161).
      --lcca-critical LCCA_CRITICAL
                            Critical threshold for lcca-6-hour
      --lcca-warning LCCA_WARNING
                            Warning threshold for lcca-6-hour
      -t TIMEOUT, --timeout TIMEOUT
                            Set the timeout for the program to run (Default: 10
                            seconds)
      -u SECNAME            Set the SNMPv3 security name (user name).
      -v VERSION            Specify the SNMP version (1, 2, 3) Default: 3
      -V, --verbose         Give verbose output (Default: False
      --signature-critical SIGNATURE_CRITICAL
                            Critical threshold for signature-6-hour
      --signature-warning SIGNATURE_WARNING
                            Warning threshold for signature-6-hour
      -x PRIVPROTOCOL       Set the SNMPv3 privacy protocol (DES or AES).
      -X PRIVPASSWORD       Set the SNMPv3 privacy pass phrase.

## Packaging for RPM

If you're thinking of packaging this little beauty up in
an RPM, you'll want to create a source package first. Here
are the steps you can use to create the source package.

1. Make sure the version of the package is correct in the VERSION file. This file is used by the packager.
2. Run the package.sh script. There are no arguments, just run it.

The source tar-ball will be created in the base directory of this
project: mirth_nagios-&lt;version&gt;.tar.bz2.

That's all.

# Copyright

Copyright (c) 2016 Dave Sieh

See LICENSE.txt for details.
