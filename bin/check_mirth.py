#!/usr/bin/env python
# encoding: utf-8
'''
check_mirth -- Call the SNMP server to gather information on Mirth Connect.

check_mirth is a Nagios plugin that uses SNMP to query a custom
back end that returns results from the Mirth application.

It defines classes_and_methods

@author:     Dave Sieh

@copyright:  2016 Dave Sieh. All rights reserved.

@license:    AGPLv3

@contact:    davesieh@gmail.com
@deffield    updated: Updated
'''
# Nagios exit codes in English
UNKNOWN  = 3
CRITICAL = 2
WARNING  = 1
OK       = 0

import sys
try:
    import netsnmp
except ImportError:
    print "Unable to load netsnmp python module, aborting!"
    sys.exit(UNKNOWN)
import os
import datetime
import time

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

# Define a TZINFO class so that we can do all our date calculations
# in UTC.
class UTC(datetime.tzinfo):
    def utcoffset(self, dt):
        return datetime.timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return datetime.timedelta(0)

# The single instance of UTC we need for our purposes.
Utc = UTC()

# Exclusion Ranges. This is a tuple of tuples of tuples (awesome).
# There are 7 tuples at the top level, one for each day of the week: Mon - 0, Sun - 6
# Within each day of the week, there is a tuple of tuples of time ranges for
# which checks are excluded. 
#
# All times are UTC.
#
EXCLUSION_RANGES = (
        # Monday
        ( ( '00:00:00', '12:00:00' ), None ),
        # Tuesday
        ( ( '00:00:00', '12:00:00' ), None ),
        # Wednesday
        ( ( '00:00:00', '12:00:00' ), None ),
        # Thursday
        ( ( '00:00:00', '12:00:00' ), None ),
        # Friday
        ( ( '00:00:00', '12:00:00' ), None ),
        # Saturday
        ( ( '00:00:00', '12:00:00' ), ( '22:00:00', '23:59:59' ) ),
        # Sunday
        ( ( '00:00:00', '12:00:00' ), ( '22:00:00', '23:59:59' ) )
        )

exit_state = {'critical': 0, 'unknown': 0, 'warning': 0}

__all__ = []
__version__ = 0.1
__date__ = '2016-10-04'
__updated__ = '2016-10-04'


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def snmpSession(options):

    hostname = options.hostname
    port = options.port
    version = options.version

#    logger.debug('Obtaining serial number via SNMP '
#                 'version: {0}.'.format(version))

    if version == 3:
        sec_level = options.secLevel
        sec_name = options.secName
        priv_protocol = options.privProtocol
        priv_password = options.privPassword
        auth_protocol = options.authProtocol
        auth_password = options.authPassword

        session = netsnmp.Session(DestHost=hostname, Version=version,
                                  SecLevel=sec_level, SecName=sec_name,
                                  AuthProto=auth_protocol,
                                  AuthPass=auth_password,
                                  PrivProto=priv_protocol,
                                  PrivPass=priv_password,
                                  RemotePort = port,
                                  )

    elif version == 2 or version == 1:
        community = options.community

        session = netsnmp.Session(DestHost=hostname, Version=version,
                                  Community=community, RemotePort=port)

    else:
        print 'Unknown SNMP version {0}, exiting!'.format(version)
        sys.exit(UNKNOWN)

    return session

def parseResults(results):
    values = {
            0 : 'lcca-1-hour',
            1 : 'lcca-6-hour',
            2 : 'signature-1-hour',
            3 : 'signature-6-hour'
            }

    final_results = {}
    for key in values:
        final_results[key] = (values[key], results[key])

    return final_results

def presentResults(results):
    finalLine = ''

    if exit_state['critical']:
        status = 'CRITICAL'
    elif exit_state['warning']:
        status = 'WARNING'
    else:
        status='OK'

    finalLine += status + ': '

    # Data to present to Nagios interface
    for item in (range(0, 4)):
        finalLine += '{0}={1} '.format(results[item][0], results[item][1])

    #Prepare parse data
    finalLine += '| '

    #Data to present perfparse
    for item in range(0, 4):
        finalLine += '{0}={1};;;; '.format(results[item][0], results[item][1])

    print finalLine

    sys.exit(eval(status))

    # This should never be reached
    return None

def queryMirth(session):

    varlist = netsnmp.VarList(netsnmp.Varbind('SNMPv2-SMI::enterprises',
                                              '.41212.11.'))
    session.walk(varlist)

    results = {}

    for var in varlist:
        # Obtain the last numeral in the OID and convert to int for the key
        results[int(var.tag.split('.')[-1])] = var.val

    return results

def createDateTime(t, st):
    st = time.strptime(st, '%H:%M:%S')
    return datetime.datetime(
            t.year, t.month, t.day, 
            st.tm_hour, st.tm_min, st.tm_sec, 
            0, Utc)

def inExclusionRange():
    t = datetime.datetime.now(Utc)

    # Get the ranges that apply to the current weekday
    day_ranges = EXCLUSION_RANGES[t.weekday()]

    inRange = False

    # Check all the registered date ranges for this
    # day of the week
    for day_range in day_ranges:
        if inRange or not day_range: continue
        t1 = createDateTime(t, day_range[0])
        t2 = createDateTime(t, day_range[1])
        inRange = t >= t1 and t <= t2
        # print "{0} = {1} >= {2} and {1} <= {3}".format(inRange, t, t1, t2)

    return inRange

def setAlarm(value, warning, critical):
    if value <= warning:
        exit_state['warning'] += 1
        if value <= critical:
            exit_state['critical'] += 1

    return None

def setAlarms(results, args):

    # We only care about two conditions:
    # 1 : 'lcca-6-hour'
    # 3 : 'signature-6-hour'

    lcca_critical = args.lcca_critical
    signature_critical = args.signature_critical
    lcca_warning = args.lcca_warning
    signature_warning = args.signature_warning

    if not inExclusionRange():
        setAlarm(int(results[1][-1]), lcca_warning, lcca_critical)

        setAlarm(int(results[3][-1]), signature_warning, signature_critical)

    return None

def sigalarmHandler(signum, frame):
    '''
    Handler for an alarm situation.
    '''

    print ('{0} timed out after {1} seconds, '
           'signum:{2}, frame: {3}').format(sys.argv[0], args.timeout,
                                            signum, frame)

    sys.exit(CRITICAL)
    return None

if __name__ == "__main__":
    '''Command line options.'''

    import signal

    argv = sys.argv

    program_name = os.path.basename(sys.argv[0])
    program_version = "v{0}".format(__version__)
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s {0} ({1})'.format(program_version,
                                                     program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''{0}

    Created by Dave Sieh on {1}.
    Copyright 2016 Dave Sieh. All rights reserved.

    Licensed under the AGPLv3
    https://www.gnu.org/licenses/agpl-3.0.html

    Distributed on an "AS IS" basis without warranties
    or conditions of any kind, either express or implied.

    USAGE
    '''.format(program_shortdesc, str(__date__))


    # Setup argument parser
    parser = ArgumentParser(description=program_license,
                            formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-a', dest='authProtocol', action='store',
                        help=('Set the default authentication protocol for '
                              'SNMPv3 (MD5 or SHA).'))
    parser.add_argument('-A', dest='authPassword',
                        help=('Set the SNMPv3 authentication protocol '
                              'password.'))
    parser.add_argument('-C', '--community', action='store',
                      dest='community', default='public',
                      help=('SNMP Community String to use.(Default: '
                            '%(default)s)'))
    parser.add_argument('hostname', action='store',
                        help='Specify the host name of the SNMP agent.')
    parser.add_argument('-l', dest='secLevel', default='noAuthNoPriv',
                        action='store',
                        help=('Set the SNMPv3 security level, (noAuthNoPriv'
                              '|authNoPriv|authPriv) (Default: %(default)s)'))
    parser.add_argument('-p', '--port', dest='port', default=161,
                        help=('Set the SNMP port to be connected to '
                              '(Default:%(default)s).'), type=int)
    parser.add_argument('--lcca-critical', type=int,
                        dest='lcca_critical',
                        help=('Critical threshold for lcca-6-hour'))
    parser.add_argument('--lcca-warning', type=int,
                        dest='lcca_warning',
                        help=('Warning threshold for lcca-6-hour'))
    parser.add_argument('-t', '--timeout', default=10,
                        help=('Set the timeout for the program to run '
                              '(Default: %(default)s seconds)'), type=int)
    parser.add_argument('-u', dest='secName', action='store',
                        help='Set the SNMPv3 security name (user name).')
    parser.add_argument('-v', dest='version', default=3, action='store',
                        help=('Specify the SNMP version (1, 2, 3) Default: '
                              '%(default)s'), type=int)
    parser.add_argument('-V', '--verbose', action='count', default=False,
                        help =('Give verbose output (Default: %(default)s'))
    parser.add_argument('--signature-critical', type=int,
                        dest='signature_critical',
                        help=('Critical threshold for signature-6-hour'))
    parser.add_argument('--signature-warning', type=int,
                        dest='signature_warning',
                        help=('Warning threshold for signature-6-hour'))
    parser.add_argument('-x', dest='privProtocol', action='store',
                        help='Set the SNMPv3 privacy protocol (DES or AES).')
    parser.add_argument('-X', dest='privPassword', action='store',
                        help='Set the SNMPv3 privacy pass phrase.')

    # Process arguments
    args = parser.parse_args()

    #Start the timer
    signal.signal(signal.SIGALRM, sigalarmHandler)
    signal.alarm(args.timeout)

    session = snmpSession(args)
    results = queryMirth(session)
    #print "Session.ErrorStr: %s" % session.ErrorStr
    #print "Session.ErrorNum: %d" % session.ErrorNum
    #print "Session.ErrorInd: %d" % session.ErrorInd
    #print "Results: %s" % results
    results = parseResults(results)
    setAlarms(results, args)

    signal.alarm(0)

    presentResults(results)

    #This shouldn't ever be reached
    sys.exit(UNKNOWN)
