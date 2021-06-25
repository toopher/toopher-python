import toopher
import unittest
import uuid
import json
from .testutils import HttpClientMock

class UserTests(unittest.TestCase):
    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret', 'https://api.toopher.test/v1')
        self.id = str(uuid.uuid4())
        self.name = 'user_name'

    def test_incomplete_response_raises_exception(self):
        response = {'key': 'value'}
        def fn():
            toopher.User(response, self.api)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_refresh_from_server(self):
        response = {
            'id': self.id,
            'name': self.name,
            'toopher_authentication_enabled': True
        }
        user = toopher.User(response, self.api)
        self.api.advanced.raw.client = HttpClientMock({
            'users/{0}'.format(user.id): (200,
                json.dumps({
                    'id': self.id,
                    'name': 'name CHANGED',
                    'toopher_authentication_enabled': False
                })
            )
        })
        user.refresh_from_server()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(user.id, self.id)
        self.assertEqual(user.name, 'name CHANGED')
        self.assertFalse(user.toopher_authentication_enabled)

    def test_enable(self):
        response = {
            'id': self.id,
            'name': self.name,
            'toopher_authentication_enabled': False
        }
        user = toopher.User(response, self.api)
        self.api.advanced.raw.client = HttpClientMock({
            'users/{0}'.format(user.id): (200,
                json.dumps({
                    'id': self.id,
                    'name': self.name,
                    'toopher_authentication_enabled': True
                })
            )
        })
        user.enable_toopher_authentication()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertTrue(self.api.advanced.raw.client.last_called_data['toopher_authentication_enabled'])
        self.assertTrue(user.toopher_authentication_enabled)

    def test_disable(self):
        response = {
            'id': self.id,
            'name': self.name,
            'toopher_authentication_enabled': True
        }
        user = toopher.User(response, self.api)
        self.api.advanced.raw.client = HttpClientMock({
            'users/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'name': self.name,
                    'toopher_authentication_enabled': False
                })
            )
        })
        user.disable_toopher_authentication()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertFalse(self.api.advanced.raw.client.last_called_data['toopher_authentication_enabled'])
        self.assertFalse(user.toopher_authentication_enabled)

    def test_reset(self):
        response = {
            'id': self.id,
            'name': self.name,
            'toopher_authentication_enabled': True}
        user = toopher.User(response, self.api)
        self.api.advanced.raw.client = HttpClientMock({
            'users/reset': (200,
                            '[]'
            )
        })
        user.reset()
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['user_name'], self.name)

    def test_update_with_incomplete_response_raises_exception(self):
        response = {
            'id': self.id,
            'name': self.name,
            'toopher_authentication_enabled': True
        }
        user = toopher.User(response, self.api)
        def fn():
            user._update({'id': self.id, 'toopher_authentication_enabled': True})
        self.assertRaises(toopher.ToopherApiError, fn)
