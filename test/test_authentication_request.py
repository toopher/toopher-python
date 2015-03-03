import unittest
import toopher
import uuid
import requests
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


class AuthenticationRequestTests(unittest.TestCase):
    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret', 'https://api.toopher.test/v1')
        self.id = str(uuid.uuid4())
        self.reason = 'it is a test'
        self.reason_code = '0'
        self.user_id = '1'
        self.user = {
            'id': self.user_id,
            'name': 'user_name',
            'toopher_authentication_enabled': True
        }
        self.terminal = {
            'id': str(uuid.uuid4()),
            'name': 'terminal_name',
            'requester_specified_id': 'requester_specified_id',
            'user': self.user
        }
        self.terminal_id = self.terminal['id']
        self.action = {
            'id': str(uuid.uuid4()),
            'name': 'action_name'
        }
        self.action_id = self.action['id']

    def test_incomplete_response_raises_exception(self):
        response = {'key': 'value'}
        def fn():
            toopher.AuthenticationRequest(response, self.api)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_nonzero_when_granted(self):
        response = ddict()
        response['granted'] = True
        allowed = toopher.AuthenticationRequest(response, self.api)
        self.assertTrue(allowed)

        response['granted'] = False
        denied = toopher.AuthenticationRequest(response, self.api)
        self.assertFalse(denied)

    def test_authenticate_with_otp(self):
        response = {
            'id': self.id,
            'pending':True,
            'granted':False,
            'automated': False,
            'reason': self.reason,
            'reason_code': self.reason_code,
            'terminal': self.terminal,
            'user': self.user,
            'action': self.action
        }
        auth_request = toopher.AuthenticationRequest(response, self.api)

        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/{0}/otp_auth'.format(auth_request.id): (200,
                json.dumps({
                    'id': self.id,
                    'pending': False,
                    'granted': True,
                    'automated': True,
                    'reason': self.reason,
                    'reason_code': self.reason_code,
                    'terminal': self.terminal,
                    'user': self.user,
                    'action': self.action
                })
            )
        })
        auth_request.grant_with_otp('otp')
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['otp'], 'otp')
        self.assertFalse(auth_request.pending)
        self.assertTrue(auth_request.granted)
        self.assertTrue(auth_request.automated)

    def test_refresh_from_server(self):
        response = {
            'id': self.id,
            'pending': False,
            'granted': True,
            'automated': False,
            'reason': self.reason,
            'reason_code': self.reason_code,
            'terminal': self.terminal,
            'user': self.user,
            'action': self.action
        }
        auth_request = toopher.AuthenticationRequest(response, self.api)

        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/{0}'.format(auth_request.id): (200,
                json.dumps({
                    'id': self.id,
                    'pending': False,
                    'granted': True,
                    'automated': True,
                    'reason': 'it is a test CHANGED',
                    'reason_code': self.reason_code,
                    'terminal': {
                        'id': self.terminal_id,
                        'name': 'terminal_name changed',
                        'requester_specified_id': 'requester_specified_id',
                        'user': self.user
                    },
                    'user': {
                        'id': self.user_id,
                        'name': 'user_name changed',
                        'toopher_authentication_enabled': False
                    },
                    'action': {
                        'id': self.action_id,
                        'name': 'action_name changed'
                    }
                })
            )
        })
        auth_request.refresh_from_server()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(auth_request.id, self.id)
        self.assertFalse(auth_request.pending)
        self.assertTrue(auth_request.granted)
        self.assertTrue(auth_request.automated)
        self.assertEqual(auth_request.reason, 'it is a test CHANGED')
        self.assertEqual(auth_request.reason_code, self.reason_code)
        self.assertEqual(auth_request.terminal.id, self.terminal_id)
        self.assertEqual(auth_request.terminal.name, 'terminal_name changed')
        self.assertEqual(auth_request.user.id, self.user_id)
        self.assertEqual(auth_request.user.name, 'user_name changed')
        self.assertFalse(auth_request.user.toopher_authentication_enabled)
        self.assertEqual(auth_request.action.id, self.action_id)
        self.assertEqual(auth_request.action.name, 'action_name changed')

    def test_update_with_incomplete_response_raises_exception(self):
        response = {
            'id': self.id,
            'pending':True,
            'granted':False,
            'automated': False,
            'reason': self.reason,
            'reason_code': self.reason_code,
            'terminal': self.terminal,
            'user': self.user,
            'action': self.action
        }
        auth_request = toopher.AuthenticationRequest(response, self.api)
        def fn():
            auth_request._update({'key': 'value'})
        self.assertRaises(toopher.ToopherApiError, fn)

class ddict(dict):
    def __getitem__(self, key):
        try:
            value = super(ddict, self).__getitem__(key)
            return value
        except KeyError as e:
            return ddict()