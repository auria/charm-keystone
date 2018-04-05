#!/usr/bin/env python3
# -*- coding: us-ascii -*-

import datetime
import ldap
import sys
from nagios_plugin3 import (
    CriticalError,
    WarnError,
    UnknownError,
)

# Thresholds (in seconds)
CRIT_T = 3
WARN_T = 1
DOMAIN_TMPL = '/etc/keystone/domains/keystone.{}.conf'


def load_file(domain):
    keys = 'url user password suffix user_filter user_id_attribute ' + \
           'chase_referrals'
    keys = keys.split()
    ldap_details = {}
    filename = DOMAIN_TMPL.format(domain)
    try:
        with open(filename) as fd:
            for line in fd.readlines():
                cols = map(lambda col: col.strip(), line.split('='))
                if cols[0] in keys and len(cols) > 1:
                    ldap_details[cols[0]] = '='.join(cols[1:])
    except Exception as e:
        msg = 'UNKNOWN: {} {}'.format(domain, e)
        raise UnknownError(msg)
    return ldap_details


def check_ldap(domain):
    ldap_details = load_file(domain)
    try:
        LDAP_SERVER = ldap_details['url']
        LDAP_USER = ldap_details['user']
        LDAP_PASSWORD = ldap_details['password']
        LDAP_BASE_DN = ldap_details['suffix']
    except KeyError as e:
        msg = 'CRITICAL: {} {}'.format(domain, e)
        raise CriticalError(msg)

    LDAP_USER_FILTER = ldap_details.get('user_filter', '')
    # NOTE(aluria): 'sAMAccount' needs to be a list of attrs
    # Sample: ['', 'sAMAccountName', 'description',
    #          'userAccountControl', 'mail']
    LDAP_ATTRS = [ldap_details.get('user_id_attribute', 'sAMAccount')]

    try:
        lclient = ldap.initialize(LDAP_SERVER)
        lclient.set_option(ldap.OPT_NETWORK_TIMEOUT, 10.0)
        if ldap_details.get('chase_referrals', 'False') in \
           ('False', 'false', 'no'):
            lclient.set_option(ldap.OPT_REFERRALS, 0)
        lclient.simple_bind_s(LDAP_USER, LDAP_PASSWORD)
    except ldap.INVALID_CREDENTIALS:
        lclient.unbind()
        msg = 'CRITICAL: {}: unable to auth with user {}'.format(domain,
                                                                 LDAP_USER)
        raise CriticalError(msg)
    except ldap.SERVER_DOWN:
        msg = 'CRITICAL: {}: server not available {}'.format(domain,
                                                             LDAP_SERVER)
        raise CriticalError(msg)

    before = datetime.datetime.now()
    try:
        resp = lclient.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE,
                                LDAP_USER_FILTER, LDAP_ATTRS)
    except Exception as e:
        msg = 'UNKNOWN: {}: {}'.format(domain, e)
        raise UnknownError(msg)

    after = datetime.datetime.now()
    lclient.unbind()
    total = after - before
    if total.seconds > CRIT_T:
        msg = 'CRITICAL: {}: request took {}s'.format(domain,
                                                      str(total.seconds))
        raise CriticalError(msg)
    elif total.seconds > WARN_T:
        msg = 'WARNING: {}: request took {}s'.format(domain,
                                                     str(total.seconds))
        raise WarnError(msg)
    else:
        print('OK: {}: request took 0.{}s'.format(domain,
                                                  str(total.microseconds)))


if __name__ == '__main__':
    if len(sys.argv) == 2:
        check_ldap(sys.argv[1])
    else:
        msg = 'UNKNOWN: no valid args: {} <domain>'.format(sys.argv[0])
        raise UnknownError(msg)
