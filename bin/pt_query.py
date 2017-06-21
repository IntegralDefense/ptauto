#!/usr/bin/env python3

import argparse
import datetime
import getpass
import json
import logging
import logging.config
import os
import re
import sys
import tabulate
import uuid

from critsapi.critsapi import CRITsAPI
from critsapi.critsdbapi import CRITsDBAPI

from lib.pt.common.config import Config
from lib.pt.common.constants import PT_HOME
from lib.pt.core.database import Database
from lib.pt.ptapi import PTAPI
from lib.crits.vocabulary.indicators import IndicatorTypes as it
from operator import itemgetter
from configparser import ConfigParser

log = logging.getLogger()
VERSION = "0.1337"

# Check configuration directory
local_config_dir = os.path.join(PT_HOME, 'etc', 'local')
if not os.path.exists(local_config_dir):
    os.makedirs(local_config_dir)
    sys.exit('No etc/local/ directory. See README to create.')

config = Config()

# Check local data directory
if config.core.cache_enabled:
    if not os.path.exists(config.core.cache_dir):
        log.info('Creating Cache directory in '
                 '{}'.format(config.core.cache_dir))
        os.makedirs(config.core.cache_dir)

# Initialize loggin
log_path = os.path.join(PT_HOME, 'etc', 'local', 'logging.ini')
try:
    logging.config.fileConfig(log_path)
except Exception as e:
    sys.exit('unable to load logging configuration file {}: '
             '{}'.format(log_path, str(e)))

pt = PTAPI(username=config.core.pt_username, apikey=config.core.pt_apikey)
pt.set_proxy(http=config.proxy.http, https=config.proxy.https)

argparser = argparse.ArgumentParser()
argparser.add_argument('QUERY', action='store', help='A value to send as a'
                       ' query to PT. Email, phone, name, etc.')
argparser.add_argument('--dev', dest='dev', action='store_true', default=False)
argparser.add_argument('--crits', dest='crits', action='store_true',
                       default=False, help='Write the results to CRITs with'
                       ' appropriate relationships.')
argparser.add_argument('--test', dest='test', action='store_true',
                       default=False, help='Run with test data. (Save PT '
                       'queries)')
argparser.add_argument('-f', dest='force', action='store_true', default=False,
                       help='Force a new API query (do not used cached '
                       'results.')
argparser.add_argument('-t', action='append', dest='tags', default=[],
                       help='Bucket list tags for crits. Multiple -t options '
                       'are allowed.')
# Add our mutually exclusive items
meg = argparser.add_mutually_exclusive_group()
meg.add_argument('-n', dest='name', action='store_true', default=False,
                 help='The query is a name and pt_query will not try to '
                 'determine the type automatically.')
meg.add_argument('-a', dest='address', action='store_true', default=False,
                 help='The query is an address and pt_query will not '
                 'try to determine the type automatically.')
args = argparser.parse_args()

# Patterns for determining which type of lookup to do
# Some items cannot be differentiated via regex (name vs address), so we use
# a flag to specify these
# Load patterns for regexes
pattern_config = ConfigParser()
patterns = {}
with open(os.path.join(PT_HOME, 'etc', 'patterns.ini')) as fp:
    pattern_config.readfp(fp)

email_address_pattern = re.compile(pattern_config.get('email', 'pattern'))
phone_pattern = re.compile(pattern_config.get('phone', 'pattern'))
domain_pattern = re.compile(pattern_config.get('domain', 'pattern'))

database = None
if config.core.cache_enabled:
    database = Database()

if args.crits:
    HOME = os.path.expanduser("~")
    if not os.path.exists(os.path.join(HOME, '.crits_api')):
        print('''Please create a file with the following contents:
            [crits]
            user = lolnate

            [keys]
            prod_api_key = keyhere
            dev_api_key = keyhere
        ''')
        raise SystemExit('~/.crits_api was not found or was not accessible.')

    crits_config = ConfigParser()
    crits_config.read(os.path.join(HOME, '.crits_api'))

    if crits_config.has_option("keys", "prod"):
        crits_api_prod = crits_config.get("keys", "prod")
    if crits_config.has_option("keys", "dev"):
        crits_api_dev = crits_config.get("keys", "dev")
    if crits_config.has_option("crits", "user"):
        crits_username = crits_config.get("crits", "user")

    if args.dev:
        crits_url = config.crits.crits_dev_api_url
        crits_api_key = crits_api_dev
        if len(crits_api_key) != 40:
            print("Dev API key in ~/.crits_api is the wrong length! Must be 40\
            characters.")
    else:
        crits_url = config.crits.crits_prod_api_url
        crits_api_key = crits_api_prod
        if len(crits_api_key) != 40:
            print("Prod API key in ~/.crits_api is the wrong length! Must be 40\
            characters.")

    crits_proxy = {
        'http': config.crits.crits_proxy_url,
        'https': config.crits.crits_proxy_url,
    }

    # Build our mongo connection
    if args.dev:
        crits_mongo = CRITsDBAPI(mongo_uri=config.crits.mongo_uri_dev,
                                 db_name=config.crits.database)
    else:
        crits_mongo = CRITsDBAPI(mongo_uri=config.crits.mongo_uri,
                                 db_name=config.crits.database)
    crits_mongo.connect()
    # Connect to the CRITs API
    crits = CRITsAPI(
        api_url=crits_url,
        api_key=crits_api_key,
        username=crits_username,
        proxies=crits_proxy,
        verify=config.crits.crits_verify
    )

query = args.QUERY.rstrip()
# Get the user launching all this
user = getpass.getuser()

# Used to store the type of indicator in CRITs for the query object.
crits_indicator_type = ''

# Used to store the cache file location
cache_file = None

if database and not args.force and config.core.cache_enabled:
    cache_file = database.get_cache_file(query)
    if cache_file:
        log.info('Using cache file for query {}'.format(query))
        with open(cache_file) as fp:
            results = json.loads(fp.read())

bucket_list = ['whois', 'pt:query']
for t in args.tags:
    bucket_list.append(t)

if args.name or args.address:
    if args.name:
        field_str = 'name'
    if args.address:
        field_str = 'address'
    if args.test:
        results = pt.get_test_results(field=field_str)
    else:
        results = pt.whois_search(query=query, field=field_str)

    if database and not cache_file and config.core.cache_enabled:
        filepath = os.path.join(config.core.cache_dir, str(uuid.uuid4()))
        log.debug('Filepath is {}'.format(filepath))
        database.add_results_to_cache(query, user, results, filepath)

    base_reference = 'https://www.passivetotal.org/search/whois/'\
                     '{}'.format(field_str)
    # Use our config defined indicator type of whois email objects
    if args.name:
        crits_indicator_type = it.WHOIS_NAME
    if args.address:
        crits_indicator_type = it.WHOIS_ADDR1

    bucket_list.append('registrant')

elif re.match(email_address_pattern, query):
    if args.test:
        results = pt.get_test_results(field='email')
    else:
        results = pt.whois_search(query=query, field='email')
    # Now add the results to the db if we have it
    if database and not cache_file and config.core.cache_enabled:
        filepath = os.path.join(config.core.cache_dir, str(uuid.uuid4()))
        log.debug('Filepath is {}'.format(filepath))
        database.add_results_to_cache(query, user, results, filepath)

    base_reference = 'https://www.passivetotal.org/search/whois/email'
    # Use our config defined indicator type of whois email objects
    crits_indicator_type = it.WHOIS_REGISTRANT_EMAIL_ADDRESS
    bucket_list.append('registrant')

elif re.match(phone_pattern, query):
    if args.test:
        results = pt.get_test_results(field='phone')
    else:
        results = pt.whois_search(query=query, field='phone')
    # Now add the results to the db if we have it
    if database and not cache_file and config.core.cache_enabled:
        filepath = os.path.join(config.core.cache_dir, str(uuid.uuid4()))
        log.debug('Filepath is {}'.format(filepath))
        database.add_results_to_cache(query, user, results, filepath)

    base_reference = 'https://www.passivetotal.org/search/whois/phone'
    crits_indicator_type = it.WHOIS_TELEPHONE
    bucket_list.append('registrant')

elif re.match(domain_pattern, query):
    if args.test:
        results = pt.get_test_results(field='domain')
    else:
        results = pt.whois_search(query=query, field='domain')
    # Now add the results to the db if we have it
    if database and not cache_file and config.core.cache_enabled:
        filepath = os.path.join(config.core.cache_dir, str(uuid.uuid4()))
        log.debug('Filepath is {}'.format(filepath))
        database.add_results_to_cache(query, user, results, filepath)

    base_reference = 'https://www.passivetotal.org/search/whois/domain'
    crits_indicator_type = it.DOMAIN

else:
    raise SystemExit("Your query didn't match a known pattern.")

# Add the query to CRITs regardless of the number of results
# TODO: Add campaigns
if args.crits:
    found = False
    # Search for it with raw mongo because API is slow
    crits_result = crits_mongo.find('indicators', {'value': query, 'type':
                                    crits_indicator_type})
    if crits_result.count() > 0:
        for r in crits_result:
            if r['value'] == query:
                indicator = r
                found = True
    if not found:
        indicator = crits.add_indicator(
            value=query,
            itype=crits_indicator_type,
            source=config.crits.default_source,
            reference='Added via pt_query.py',
            method='pt_query.py',
            bucket_list=bucket_list,
            indicator_confidence='low',
            indicator_impact='low',
            description='Queried with pt_query.py',
        )

    # This is pretty hacky - Since we use both the raw DB and the API, we might
    # receive either an '_id' or an 'id' back. We are going to standardize on
    # 'id', rather than '_id'
    if 'id' not in indicator:
        if '_id' not in indicator:
            print(repr(indicator))
            raise SystemExit('id and _id not found for query: '
                             '{} in new indicator'.format(query))
        else:
            indicator['id'] = indicator['_id']

# Iterate through all results and print/add to CRITs (if args provided)
formatted_results = []
for result in results['results']:
    if 'domain' in result:
        crits_indicators_to_add = []
        # Row contains:
        # Domain, Registrant Email, Registrant Name, Registrant Date,
        # Expiration Date, Tags
        row = ['', '', '', '', '', '']
        row[0] = result['domain']
        # Email address used to register
        if 'registrant' in result:
            # Append the registrant email
            if 'email' in result['registrant']:
                row[1] = result['registrant']['email']
                email_obj = {
                    'value': result['registrant']['email'],
                    'type': it.WHOIS_REGISTRANT_EMAIL_ADDRESS,
                    'related_to': result['domain']
                }
                crits_indicators_to_add.append(email_obj)
            if 'name' in result['registrant']:
                row[2] = result['registrant']['name']
                name_obj = {
                    'value': result['registrant']['name'],
                    'type': it.WHOIS_NAME,
                    'related_to': result['domain']
                }
                crits_indicators_to_add.append(name_obj)
            if 'telephone' in result['registrant']:
                row[3] = result['registrant']['telephone']
                phone_obj = {
                    'value': result['registrant']['telephone'],
                    'type': it.WHOIS_TELEPHONE,
                    'related_to': result['domain']
                }
                crits_indicators_to_add.append(phone_obj)
            if 'street' in result['registrant']:
                addr1_obj = {
                    'value': result['registrant']['street'],
                    'type': it.WHOIS_ADDR1,
                    'related_to': result['domain']
                }
                crits_indicators_to_add.append(addr1_obj)

        # Date the domain was registered
        if 'registered' in result:
            row[4] = result['registered']
        if 'expiresAt' in result:
            row[5] = result['expiresAt']
        formatted_results.append(row)
        # TODO: Tags. They appear to be an extra API query which is annoying

        reference = '{0}/{1}'.format(base_reference, query)

        if args.crits:
            # Let's try getting the confidence and impact from the parent whois
            # indicator
            confidence = 'low'
            impact = 'low'
            if 'confidence' in indicator:
                if 'rating' in indicator['confidence']:
                    confidence = indicator['confidence']['rating']
            if 'impact' in indicator:
                if 'rating' in indicator['impact']:
                    impact = indicator['impact']['rating']
            # If not in CRITs, add all the associated indicators
            bucket_list = ['whois pivoting', 'pt:found']
            for t in args.tags:
                bucket_list.append(t)
            new_ind = crits.add_indicator(
                value=result['domain'],
                itype=it.DOMAIN,
                source=config.crits.default_source,
                reference=reference,
                method='pt_query.py',
                bucket_list=bucket_list,
                indicator_confidence=confidence,
                indicator_impact=impact,
                description='Discovered through PT whois pivots'
            )

            # The CRITs API allows us to add a campaign to the indicator, but
            # not multiple campaigns at one time,
            # so we will do it directly with the DB.
            # We want to replicate the campaigns of the WHOIS indicator (if
            # a campaign exists) to the new indicator.
            if 'campaign' in indicator:
                for campaign in indicator['campaign']:
                    crits_mongo.add_embedded_campaign(
                        new_ind['id'],
                        'indicators',
                        campaign['name'],
                        campaign['confidence'],
                        campaign['analyst'],
                        datetime.datetime.now(),
                        campaign['description']
                    )

            # If the new indicator and the indicator are not related,
            # relate them.
            if not crits.has_relationship(indicator['id'], 'Indicator',
                                          new_ind['id'], 'Indicator',
                                          rel_type='Registered'):
                crits.forge_relationship(indicator['id'], 'Indicator',
                                         new_ind['id'], 'Indicator',
                                         rel_type='Registered')

            # Now we can add the rest of the WHOIS indicators (if necessary)
            for ind in crits_indicators_to_add:
                # If the indicator exists, just get the id and use it to build
                # relationships. We will look for one with the same source.
                # If not in CRITs, add it and relate it.
                whois_indicator = crits_mongo.find_one(
                    'indicators',
                    {
                        'value': ind['value'],
                        'type': ind['type'],
                        'source.name':
                        config.crits.default_source,
                    })
                if not whois_indicator:
                    bucket_list = ['whois pivoting', 'pt:found']
                    for t in args.tags:
                        bucket_list.append(t)
                    whois_indicator = crits.add_indicator(
                        value=ind['value'],
                        itype=ind['type'],
                        source=config.crits.default_source,
                        reference=reference,
                        method='pt_query.py',
                        bucket_list=bucket_list,
                        indicator_confidence=confidence,
                        indicator_impact=impact,
                        description='Discovered through PT whois pivots'
                    )

                # This is pretty hacky - Since we use both the raw DB and the
                # API, we might receive either an '_id' or an 'id' back. We
                # are going to standardize on 'id', rather than '_id'
                if 'id' not in whois_indicator:
                    if '_id' not in whois_indicator:
                        print(repr(whois_indicator))
                        raise SystemExit('id and _id not found for query: '
                                         '{} in whois indicator'.format(query))
                    whois_indicator['id'] = whois_indicator['_id']

                # Not a huge deal, but make sure we don't waste time adding
                # a relationship to itself
                if whois_indicator['id'] == new_ind['id']:
                    continue
                # The CRITs API allows us to add a campaign to the indicator,
                # but not multiple campaigns at one time,
                # so we will do it directly with the DB.
                # We want to replicate the campaigns of the WHOIS indicator (if
                # a campaign exists) to the new indicator.
                # Continue with the same campaign
                if 'campaign' in indicator:
                    for campaign in indicator['campaign']:
                        crits_mongo.add_embedded_campaign(
                            whois_indicator['id'],
                            'indicators',
                            campaign['name'],
                            campaign['confidence'],
                            campaign['analyst'],
                            datetime.datetime.now(),
                            campaign['description']
                        )

                # If the new indicator and the indicator are not related,
                # relate them.
                if not crits.has_relationship(whois_indicator['id'],
                                              'Indicator',
                                              new_ind['id'],
                                              'Indicator',
                                              rel_type='Registered'):
                    crits.forge_relationship(whois_indicator['id'],
                                             'Indicator',
                                             new_ind['id'],
                                             'Indicator',
                                             rel_type='Registered')

# Add a bucket_list item to track that we searched for this whois indicator
if args.crits:
    crits_mongo.add_bucket_list_item(indicator['id'], 'indicators',
                                     'pt:whois_search_completed')

# SORT BY DATE
formatted_results = sorted(formatted_results, key=itemgetter(3), reverse=True)
# Row contains:
# Domain, Registrant Email, Registrant Name, Registrant Telephone,
# Registrant Date, Expiration Date, Tags
headers = ['Domain', 'Registrant Email', 'Registrant Name',
           'Registrant Telephone', 'Registrant Date', 'Expiration Date',
           'Tags']
print(tabulate.tabulate(formatted_results, headers))
