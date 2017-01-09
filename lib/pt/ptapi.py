import json
import logging
import requests

from requests.auth import HTTPBasicAuth

log = logging.getLogger()

class PTAPI():
    def __init__(self, username='', apikey=''):
        self.username = username
        self.apikey = apikey
        self.proxies = {}

    def set_proxy(self, http='', https=''):
        self.proxies = {
            'http' : http,
            'https' : https
        }

    def whois_search(self, query='', field=''):
        """
        Performs a WHOIS search with the given parameters

        :param query: the search term
        :type str:
        :param field: WHOIS field to execute the search on: domain, email,
                      name, organization, address, phone, nameserver
        :type str:
        :returns dict using json.loads()
        """
        log.debug('Permforming WHOIS search with query: {0} and field: '
                  '{1}'.format(query, field))
        params = { 'query' : query, 'field' : field }
        r = requests.get('https://api.passivetotal.org/v2/whois/search',
                         auth=HTTPBasicAuth(self.username, self.apikey),
                         proxies=self.proxies, params=params)
        if r.status_code == 200:
            results = json.loads(r.text)
            return results
        else:
            log.error('HTTP code {0} returned during WHOIS search '
                      'request.'.format(r.status_code))
            return None

    def get_test_results(self, field=''):
        """
        Returns test results not using the PT API
        """
        with open('lib/pt/test/{}.test'.format(field)) as fp:
            data = fp.read()
        results = json.loads(data)
        return results
