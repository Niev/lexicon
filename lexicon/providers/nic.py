from __future__ import absolute_import
from __future__ import print_function

import logging
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import Element

import requests

from lexicon.providers.base import Provider as BaseProvider

logger = logging.getLogger(__name__)


def ProviderParser(subparser):
    subparser.add_argument("--auth-username", help="specify username. Example: 123456/NIC-D")
    subparser.add_argument("--auth-password", help="specify admin or technical password")
    subparser.add_argument("--auth-client-id", help="specify OAuth client identity")
    subparser.add_argument("--auth-token", help="specify OAuth client secret")


class Provider(BaseProvider):

    def __init__(self, options, engine_overrides=None):
        super(Provider, self).__init__(options, engine_overrides)
        self.domain_id = None
        self.service = None
        self.zone = None
        self.auth_data = None
        self.api_endpoint = self.engine_overrides.get('api_endpoint', 'https://api.nic.ru')

    def authenticate(self):
        payload = self._get('/dns-master/zones')
        tree = ET.fromstring(payload)

        zones = tree.findall(".//*/zone")
        logger.debug('list zones: %s', (zone.attrib for zone in zones))

        for zone in zones:
            if zone.get('idn-name') == self.options['domain']:
                self.domain_id = self.options['domain']
                self.service = zone.get('service')
                self.zone = zone.get('name')
                return self.domain_id

        raise Exception('No domain found')

    def create_record(self, type, name, content):
        if (type == 'CNAME') or (type == 'MX') or (type == 'NS'):
            content = content.rstrip('.') + '.' # make sure a the data is always a FQDN for CNAMe.

        check_exists = self.list_records(type=type, name=name, content=content)
        if not len(check_exists) > 0:
            records = (
                '<?xml version="1.0" encoding="UTF-8" ?>'
                '<request>'
                    '<rr-list>'
                        '<rr>'
                            '<name>{name}</name>'
                            '<type>{type}</type>'
                            '{record}'
                        '</rr>'
                    '</rr-list>'
                '</request>'
            ).format(
                type=type,
                name=name,
                record=self._make_record_xml(type=type, name=name, content=content)
            )

            self._put(
                self.api_endpoint + '/dns-master/services/{0}/zones/{1}/records'.format(self.service, self.zone),
                data=records
            )
            return True
        return False

    # List all records. Return an empty list if no records found
    # type, name and content are used to filter records.
    # If possible filter during the query, otherwise filter after response is received.
    def list_records(self, type=None, name=None, content=None):
        payload = self._get('/dns-master/services/{0}/zones/{1}/records'.format(self.service, self.zone))

        tree = ET.fromstring(payload)
        records = [
            {
                'id': rec.get('id'),
                'name': rec.findtext('name'),
                'type': rec.findtext('type'),
                'content': self._get_record_content(rec),
            } for rec in tree.findall(".//*/rr")
        ]

        if type:
            records = [record for record in records if record['type'] == type]
        if name:
            records = [record for record in records if record['name'] == name]
        if content:
            records = [record for record in records if record['content'].lower() == content.lower()]

        logger.debug('list_records: %s', records)
        return records

    # Just update existing record. Domain ID (domain) and Identifier (record_id) is mandatory
    def update_record(self, identifier, type=None, name=None, content=None):
        if self.delete_record(identifier, type, name):
            return self.create_record(type, name, content)
        return False

    # Delete an existing record.
    # If record does not exist (I'll hope), do nothing.
    def delete_record(self, identifier=None, type=None, name=None, content=None):
        if not identifier:
            records = self.list_records(type, name, content)
            logger.debug('records: %s', records)
            if len(records) == 1:
                identifier = records[0]['id']
            else:
                raise Exception('Record identifier can not be determined unambiguously')

        self._delete('/dns-master/services/{0}/zones/{1}/records/{2}'.format(self.service, self.zone, identifier))
        return True

    # Helpers
    def _request(self, action='GET',  url='/', data=None, query_params=None):
        if data is None:
            data = {}
        if query_params is None:
            query_params = {}

        if not url.startswith(self.api_endpoint):
            url = self.api_endpoint + url

        if self.auth_data is None:
            self.auth_data = self._auth()

        default_headers = {
            'Authorization': '{token_type} {token}'.format(
                token_type=self.auth_data.get('token_type'),
                token=self.auth_data.get('access_token')
            )
        }

        logger.debug('Auth: %s', self.auth_data)

        r = requests.request(action, url, params=query_params,
                             data=data,
                             headers=default_headers)
        r.raise_for_status()  # if the request fails for any reason, throw an error.
        if action == 'DELETE':
            return ''
        else:
            return r.text

    def _auth(self):
        payload = requests.post('{0}/oauth/token'.format(self.api_endpoint), data={
            'grant_type': 'password',
            'scope': '(GET|PUT|POST|DELETE):/dns-master/.+',
            'username': self.options.get('auth_username'),
            'password': self.options.get('auth_password'),
            'client_id': self.options.get('auth_client_id'),
            'client_secret': self.options.get('auth_token')
        })

        return payload.json()

    @staticmethod
    def _get_record_content(elem: Element):
        elem_type = elem.findtext('type')
        if elem_type == 'TXT':
            return "\n".join([
                rec_string.text for rec_string in elem.find('txt').findall('string')
            ])
        elif elem_type == 'A':
            return elem.findtext('a')
        elif elem_type == 'AAAA':
            return elem.findtext('aaaa')
        elif elem_type == 'NS':
            return elem.find('ns').findtext('name')
        elif elem_type == 'CNAME':
            return elem.find('cname').findtext('name')
        elif elem_type == 'MX':
            return elem.find('mx').find('exchange').findtext('name')
        elif elem_type == 'SRV':
            return elem.find('srv').find('target').findtext('name')
        elif elem_type == 'PTR':
            return elem.find('ptr').findtext('name')
        elif elem_type == 'DNAME':
            return elem.find('dname').findtext('name')
        elif elem_type == 'HINFO':
            return {
                children.tag: children.text
                for children in elem.find('hinfo').getChildren()
            }
        elif elem_type == 'NAPTR':
            return {
                children.tag: children.findtext('name') if children.find('name') else children.text
                for children in elem.find('naptr').getchildren()
            }
        elif elem_type == 'RP':
            return {
                children.tag: children.findtext('name') if children.find('name') else children.text
                for children in elem.find('rp').getchildren()
            }
        elif elem_type == 'SOA':
            return {
                children.tag: children.findtext('name') if children.find('name') else children.text
                for children in elem.find('soa').getchildren()
            }
        else:
            return

    @staticmethod
    def _make_record_xml(type, name, content):
        tag = type.lower()
        text = content

        if type == 'A':
            return '<{tag}>{text}</{tag}>'.format(tag=tag, text=content)
        if type == 'AAAA':
            return '<{tag}>{text}</{tag}>'.format(tag=tag, text=content)
        if type == 'MX':
            return '<{tag}><exchange><name>{text}</name></exchange></{tag}>'.format(tag=tag, text=text)
        if type == 'SRV':
            return '<{tag}><target><name>{text}</name></target></{tag}>'.format(tag=tag, text=text)
        elif type == 'TXT':
            text = '\n'.join(['<string>{}</string>'.format(txt) for txt in content.split('\n')])
            return '<{tag}>{text}</{tag}>'.format(tag=tag, text=text)
        else:
            return '<{tag}><name>{text}</name></{tag}>'.format(tag=type, text=content)
