import toopher
import unittest
import requests
import uuid
import json

class HttpClientMock(object):
    def __init__(self, paths):
        self.paths = paths

    def request(self, method, uri, data=None, headers=None, params=None):
        self.last_called_uri = uri
        self.last_called_method = method
        self.last_called_data = data if data else params
        self.last_called_headers = headers

        uri = uri.split(toopher.DEFAULT_BASE_URL)[1][1:]
        if uri in self.paths:
            return ResponseMock(self.paths[uri])
        else:
            return ResponseMock((400, '{}'))


class ResponseMock(requests.Response):
    def __init__(self, response):
        self.encoding = 'utf-8'
        self.status_code = int(response[0])
        self._content = response[1]


class PairingTests(unittest.TestCase):
    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret', 'https://api.toopher.test/v1')
        self.id = str(uuid.uuid4())
        self.user = {
            'id': str(uuid.uuid4()),
            'name': 'user_name',
            'toopher_authentication_enabled': True
        }
        self.user_id = self.user['id']
        self.user_name = self.user['name']

    def test_incomplete_response_raises_exception(self):
        response = {'key': 'value'}
        def fn():
            toopher.Pairing(response, self.api)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_nonzero_when_granted(self):
        response = ddict()
        response['enabled'] = True
        allowed = toopher.Pairing(response, self.api)
        self.assertTrue(allowed)

        response['enabled'] = False
        denied = toopher.Pairing(response, self.api)
        self.assertFalse(denied)

    def test_refresh_from_server(self):
        response = {
            'id': self.id,
            'enabled': True,
            'pending': True,
            'user': self.user
        }
        pairing = toopher.Pairing(response, self.api)

        self.api.advanced.raw.client = HttpClientMock({
            'pairings/{0}'.format(pairing.id): (200,
                json.dumps({
                    'id': self.id,
                    'enabled': False,
                    'pending': False,
                    'user': {
                        'id': self.user_id,
                        'name': 'user_name changed',
                        'toopher_authentication_enabled': False
                    }
                })
            )
        })
        pairing.refresh_from_server()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(pairing.id, self.id)
        self.assertEqual(pairing.user.id, self.user_id)
        self.assertEqual(pairing.user.name, 'user_name changed')
        self.assertFalse(pairing.user.toopher_authentication_enabled)
        self.assertFalse(pairing.enabled)
        self.assertFalse(pairing.pending)

    def test_get_qr_code_image(self):
        response = {'id': self.id,
                    'enabled': True,
                    'pending': True,
                    'user': self.user }
        pairing = toopher.Pairing(response, self.api)
        self.api.advanced.raw.client = HttpClientMock({
            'qr/pairings/{0}'.format(pairing.id): (200,
                    '{}')
        })
        pairing.get_qr_code_image()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(self.api.advanced.raw.client.last_called_uri, 'https://api.toopher.test/v1/qr/pairings/{0}'.format(pairing.id))

    def test_get_reset_link(self):
        response = {'id':self.id,
                    'enabled': False,
                    'pending': True,
                    'user': self.user }
        pairing = toopher.Pairing(response, self.api)

        self.api.advanced.raw.client = HttpClientMock({
            'pairings/{0}/generate_reset_link'.format(self.id): (200,
                json.dumps({
                    'url': 'http://api.toopher.test/v1/pairings/{0}/reset?reset_authorization=abcde'.format(self.id)
                })
            )
        })
        reset_link = pairing.get_reset_link()
        self.assertEqual('http://api.toopher.test/v1/pairings/{0}/reset?reset_authorization=abcde'.format(self.id), reset_link)

    def test_email_reset_link(self):
        response = {'id':self.id,
                    'enabled': False,
                    'pending': True,
                    'user': self.user }
        pairing = toopher.Pairing(response, self.api)
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/{0}/send_reset_link'.format(self.id): (201,
                                           '[]'
            )
        })
        try:
            pairing.email_reset_link('email')
        except toopher.ToopherApiError as e:
            self.fail('pairing.email_reset_link() returned a status code of >= 400: %s' % e)


    def test_update_with_incomplete_response_raises_exception(self):
        response = {'id': self.id,
                    'enabled': False,
                    'pending': True,
                    'user': self.user
        }
        pairing = toopher.Pairing(response, self.api)
        def fn():
            pairing._update({'id': self.id, 'pending': True, 'user': self.user})
        self.assertRaises(toopher.ToopherApiError, fn)

class ddict(dict):
    def __getitem__(self, key):
        try:
            value = super(ddict, self).__getitem__(key)
            return value
        except KeyError as e:
            return ddict()