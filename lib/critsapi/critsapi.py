import datetime
import json
import logging
import requests

from lib.crits.exceptions import CRITsOperationalError
from lib.crits.vocabulary.indicators import IndicatorThreatTypes as itt
from lib.crits.vocabulary.indicators import IndicatorAttackTypes as iat

log = logging.getLogger()

class CRITsAPI():

    def __init__(self, api_url='', api_key='', username='', verify=True,
                 proxies={}):
        self.url = api_url
        if self.url[-1] == '/':
            self.url = self.url[:-1]
        self.api_key = api_key
        self.username = username
        self.verify = verify
        self.proxies = proxies

    def get_object(self, obj_id, obj_type):
        type_trans = self._type_translation(obj_type)
        get_url = '{}/{}/{}/'.format(self.url, type_trans, obj_id)
        params = {
            'username' : self.username,
            'api_key' : self.api_key,
        }
        r = requests.get(get_url, params=params, proxies=self.proxies, verify=self.verify)
        if r.status_code == 200:
            return json.loads(r.text)
        else:
            print('Status code returned for query {}, '
                  'was: {}'.format(get_url, r.status_code))
        return None

    def add_indicator(self, source = '', reference = '', method = '',
            campaign = None, confidence = None, bucket_list = [], ticket = '',
            add_domain = True, add_relationship = True,
            indicator_confidence = 'unknown', indicator_impact = 'unknown',
            type = None, threat_type = itt.UNKNOWN, attack_type = iat.UNKNOWN,
            value = None, description = ''):
        # Time to upload these indicators
        data = {
            'api_key' : self.api_key,
            'username' : self.username,
            'source' : source,
            'reference' : reference,
            'method' : '',
            'campaign' : campaign,
            'confidence' : confidence,
            'bucket_list' : bucket_list,
            'ticket' : ticket,
            'add_domain' : True,
            'add_relationship' : True,
            'indicator_confidence' : indicator_confidence,
            'indicator_impact' : indicator_impact,
            'type' : type,
            'threat_type' : threat_type,
            'attack_type' : attack_type,
            'value' : value,
            'description' : description,
            }

        r = requests.post("{0}/indicators/".format(self.url), data=data,
                          verify=self.verify, proxies=self.proxies)
        if r.status_code == 200:
            log.debug("Indicator uploaded successfully - {}".format(value))
            ind = json.loads(r.text)
            return ind

        return None

    def has_relationship(self, left_id, left_type, right_id, right_type,
                         rel_type='Related To'):
        data = self.get_object(left_id, left_type)
        if not data:
            raise CRITsOperationalError('Crits Object not found with id {} and '
                                        'type {}'.format(left_id, left_type))
        if not 'relationships' in data:
            return False
        for relationship in data['relationships']:
            if relationship['relationship'] != rel_type:
                continue
            if relationship['value'] != right_id:
                continue
            if relationship['type'] != right_type:
                continue
            return True
        return False

    def forge_relationship(self, left_id, left_type, right_id, right_type,
                           rel_type, rel_date='', rel_confidence='high',
                           rel_reason=''):
        if not rel_date:
            rel_date = datetime.datetime.now()
        type_trans = self._type_translation(left_type)
        submit_url = '{}/{}/{}/'.format(self.url, type_trans, left_id)
        headers = {
            'Content-Type' : 'application/json',
            }

        params = {
            'api_key' : self.api_key,
            'username' : self.username,
            }

        data = {
            'action' : 'forge_relationship',
            'right_type' : right_type,
            'right_id' : right_id,
            'rel_type' : rel_type,
            'rel_date' : rel_date,
            'rel_confidence' : rel_confidence,
            'rel_reason' : rel_reason
        }

        r = requests.patch(submit_url, params=params, data=data,
                           proxies=self.proxies, verify=self.verify)
        if r.status_code == 200:
            log.debug('Relationship built successfully: {0} <-> '
                     '{1}'.format(left_id, right_id))
            return True
        else:
            log.error('Error with status code {0} and message {1} between '
                      'these indicators: {2} <-> '
                      '{3}'.format(r.status_code, r.text, left_id, right_id))
            return False

    def add_campaign_to_object(self, id, type, campaign, confidence, analyst,
                               date, description):
        # TODO: Make sure the object does not already have the campaign
        # Return if it does. Add it if it doesn't
        obj = getattr(self.db, type)
        result = obj.find( { '_id' : id, 'campaign.name' : campaign } )
        if result:
            import pdb
            pdb.set_trace()

    def _type_translation(self, str_type):
        if str_type == 'Indicator':
            return 'indicators'
        if str_type == 'Domain':
            return 'domains'
        if str_type == 'IP':
            return 'ips'
        if str_type == 'Sample':
            return 'samples'
        if str_type == 'Event':
            return 'events'
        if str_type == 'Actor':
            return 'actors'
        if str_type == 'Email':
            return 'emails'
        if str_type == 'Backdoor':
            return 'backdoors'

        raise CRITsOperationalError('Invalid object type specified: '
                                    '{}'.format(str_type))
