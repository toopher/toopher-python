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

class UserTerminalTests(unittest.TestCase):
    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret')
        self.id = str(uuid.uuid4())
        self.name = 'name'
        self.requester_specified_id = 'requester_specified_id'
        self.user = {
            'id': str(uuid.uuid4()),
            'name': 'user_name',
            'toopher_authentication_enabled': True
        }
        self.user_id = self.user['id']

    def test_incomplete_response_raises_exception(self):
        response = {'key': 'value'}
        def fn():
            toopher.UserTerminal(response, self.api)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_refresh_from_server(self):
        response = {
            'id': self.id,
            'name': self.name,
            'requester_specified_id': self.requester_specified_id,
            'user': self.user
        }
        user_terminal = toopher.UserTerminal(response, self.api)
        self.api.advanced.raw.client = HttpClientMock({
            'user_terminals/{0}'.format(user_terminal.id): (200,
                json.dumps({
                    'id': self.id,
                    'name': 'name changed',
                    'requester_specified_id': 'requester_specified_id changed',
                    'user': {
                        'id': self.user_id,
                        'name': 'user_name changed',
                        'toopher_authentication_enabled': False
                    }
                })
            )
        })
        user_terminal.refresh_from_server()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(user_terminal.id, self.id)
        self.assertEqual(user_terminal.name, 'name changed')
        self.assertEqual(user_terminal.requester_specified_id, 'requester_specified_id changed')
        self.assertEqual(user_terminal.user.name, 'user_name changed')
        self.assertEqual(user_terminal.user.id, self.user_id)
        self.assertFalse(user_terminal.user.toopher_authentication_enabled)

    def test_update_with_incomplete_response_raises_exception(self):
        response = {
            'id': self.id,
            'name': self.name,
            'requester_specified_id': self.requester_specified_id,
            'user': self.user
        }
        user_terminal = toopher.UserTerminal(response, self.api)
        def fn():
            user_terminal._update({'id': self.id, 'requester_specified_id': self.requester_specified_id, 'user': self.user})
        self.assertRaises(toopher.ToopherApiError, fn)