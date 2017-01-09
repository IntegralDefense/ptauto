#!/usr/bin/env python3

import argparse
import getpass
import json
import logging, logging.config
import os
import re
import sys
import tabulate
import uuid

from lib.critsapi.critsapi import CRITsAPI
from lib.pt.common.config import Config
from lib.pt.core.database import Database
from lib.pt.ptapi import PTAPI
from lib.crits.vocabulary.indicators import IndicatorTypes as it
from operator import itemgetter
from pymongo import MongoClient
from configparser import ConfigParser

# Check configuration directory
local_config_dir = os.path.join('etc', 'local')
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
log_path = os.path.join('etc', 'local', 'logging.ini')
try:
    logging.config.fileConfig(log_path)
except Exception as e:
    sys.exit('unable to load logging configuration file {}: '
             '{}'.format(log_path, str(e)))

log = logging.getLogger()

email_address_pattern = re.compile('([a-zA-Z][_a-zA-Z0-9-.]+@[a-z0-9-]+(?:\.[a-z]+)+)')
phone_pattern = re.compile('^[0-9]{9,15}$')

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
args = argparser.parse_args()

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
        'http' : config.crits.crits_proxy_url,
        'https' : config.crits.crits_proxy_url,
    }

    # Build our mongo connection
    client = MongoClient(config.crits.mongo_uri)
    db = client[config.crits.database]
    # Connect to the CRITs API
    crits = CRITsAPI(
        api_url=crits_url,
        api_key=crits_api_key,
        username=crits_username,
        proxies=crits_proxy
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

if re.match(email_address_pattern, query):
    # Store in config.core.cache_dir
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
    crits_indicator_type = getattr(it, config.crits.whois_email_type)

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

else:
    raise SystemExit("Your query didn't match a known pattern.")

# Add the query to CRITs regardless of the number of results
if args.crits:
    found = False
    # Search for it with raw mongo because API is slow
    crits_result = db.indicators.find( { 'value' : query, 'type' : crits_indicator_type } )
    if crits_result.count() > 0:
        for r in crits_result:
            if r['value'] == query:
                indicator = r
                found = True
    if not found:
        indicator = crits.add_indicator(
            source = config.crits.default_source,
            reference = 'Added via pt_query.py',
            method = 'pt_query.py',
            bucket_list = 'registrant,whois,pt:query',
            indicator_confidence = 'low',
            indicator_impact = 'low',
            type = crits_indicator_type,
            value = query,
            description = 'Queried with pt_query.py',
        )

    if '_id' not in indicator:
        raise SystemExit('Bad indicator object from CRITs for value '
                         '{}'.format(query))

# Iterate through all results and print/add to CRITs (if args provided)
formatted_results = []
for result in results['results']:
    if 'domain' in result:
        # Row contains:
        # Domain, Registrant Email, Registrant Name, Registrant Date,
        # Expiration Date, Tags
        row = [ '', '', '', '', '', '']
        row[0] = result['domain']
        # Email address used to register
        if 'registrant' in result:
            # Append the registrant email
            if 'email' in result['registrant']:
                row[1] = result['registrant']['email']
            if 'name' in result['registrant']:
                row[2] = result['registrant']['name']
        # Date the domain was registered
        if 'registered' in result:
            row[3] = result['registered']
        if 'expiresAt' in result:
            row[4] = result['expiresAt']
        formatted_results.append(row)
        # TODO: Tags. They appear to be an extra API query which is annoying

        email_reference = '{0}/{1}'.format(base_reference, query)

        if args.crits:
            # Let's try getting the confidence and impact from the parent whois
            # indicator
            confidence = 'medium'
            impact = 'medium'
            if 'confidence' in indicator:
                confidence = indicator['confidence']
            if 'impact' in indicator:
                impact = indicator['impact']
            # If not in CRITs, add it.
            new_ind = crits.add_indicator(
                source = config.crits.default_source,
                reference = email_reference,
                method = 'pt.py',
                bucket_list = 'whois pivoting,pt:found',
                indicator_confidence = confidence,
                indicator_impact = impact,
                type = it.DOMAIN,
                value = result['domain'],
                description = 'Discovered through PT whois pivots'
            )

            # The CRITs API does not allow us to add a campaign,
            # so we will do it directly with the DB.
            # We want to replicate the campaigns of the WHOIS indicator
            # to the new indicator.
            if 'campaign' in indicator:
                for campaign in indicator['campaign']:
                    campaign_obj = {
                        'analyst' : campaign['analyst'],
                        'confidence' : campaign['confidence'],
                        'date' : campaign['date'],
                        'description' : campaign['description'],
                        'name' : campaign['name']
                    }
                    db.indicators.update( { '_id' : new_ind['id'] },
                        { '$addToSet' : { 'campaign' : campaign_obj } } )

            # If the new indicator and the indicator are not related, relate them.
            if not crits.has_relationship(indicator['_id'], 'Indicator',
                                          new_ind['id'], 'Indicator',
                                          rel_type='Registered'):
                crits.forge_relationship(indicator['_id'], 'Indicator',
                                         new_ind['id'], 'Indicator',
                                         rel_type='Registered')

# Add a bucket_list item to track that we searched for this whois indicator
if args.crits:
    update_status = db.indicators.update( { '_id' : indicator['_id'] },
        { '$addToSet' : { 'bucket_list' : 'pt:whois_search_completed' } } )

# SORT BY DATE
formatted_results = sorted(formatted_results, key=itemgetter(3), reverse=True)
# Row contains:
# Domain, Registrant Email, Registrant Name, Registrant Date,
# Expiration Date, Tags
headers = [ 'Domain', 'Registrant Email', 'Registrant Name', 'Registrant Date',
           'Expiration Date', 'Tags' ]
print(tabulate.tabulate(formatted_results, headers))
