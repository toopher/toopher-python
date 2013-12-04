import json
import toopher
import requests
import unittest

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
            return {'status': 400}, ''

class ResponseMock(requests.Response):
    def __init__(self, response):
        self.encoding = 'utf-8'
        self.status_code = int(response[0]['status'])
        self._content = response[1]

class ToopherTests(unittest.TestCase):
    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    def test_constructor(self):
        with self.assertRaises(TypeError):
            api = toopher.ToopherApi()

        api = toopher.ToopherApi('key', 'secret')

    def test_version_number_in_library(self):
        major, minor, patch = toopher.VERSION.split('.')
        self.assertGreaterEqual(int(major), 1)
        self.assertGreaterEqual(int(minor), 0)
        self.assertGreaterEqual(int(patch), 0)

    def test_version_number_in_setup(self):
        ''' Ensure that the setup.py file has the same version number as the toopher/__init__.py file '''
        for line in open('setup.py'):
            if "version" in line:
                # in setup.py the version is written as "version='1.0.6'," so we need to remove version=' and ',
                version_number = line.strip().replace("version='", "").replace("',", "")
                self.assertEqual(version_number, toopher.VERSION)

    def test_create_pairing(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'pairings/create':(
                {'status':'200'},
                '{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}'
                )
            })
        pairing = api.pair('awkward turtle', 'some user')

        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(api.client.last_called_data['pairing_phrase'], 'awkward turtle')
        with self.assertRaises(KeyError):
            self.assertEqual(api.client.last_called_data['test_param'], ['42'])

    def test_pairing_status(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'pairings/1':(
                {'status':'200'},
                '{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}'
                )
            })
        pairing = api.get_pairing_status('1')
        self.assertEqual(api.client.last_called_method, 'GET')

        self.assertEqual(pairing.id, '1')
        self.assertEqual(pairing.user_name, 'some user')
        self.assertEqual(pairing.user_id, '1')
        self.assertTrue(pairing.enabled)

        with self.assertRaises(KeyError):
            foo = pairing.random_key

    def test_create_authentication_request(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate':(
                {'status':'200'},
                '{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}'
                )
            })
        auth_request = api.authenticate('1', 'test terminal')
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(api.client.last_called_data['pairing_id'], '1')
        self.assertEqual(api.client.last_called_data['terminal_name'], 'test terminal')
        with self.assertRaises(KeyError):
            self.assertEqual(api.client.last_called_data['test_param'], '42')

    def test_authentication_status(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/1':(
                {'status':'200'},
                '{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}'
                )
            })
        auth_request = api.get_authentication_status('1')
        self.assertEqual(api.client.last_called_method, 'GET')
        self.assertEqual(auth_request.id, '1')
        self.assertFalse(auth_request.pending, False)
        self.assertTrue(auth_request.granted)
        self.assertFalse(auth_request.automated)
        self.assertEqual(auth_request.reason, 'its a test')
        self.assertEqual(auth_request.terminal_id, '1')
        self.assertEqual(auth_request.terminal_name, 'test terminal')

        with self.assertRaises(KeyError):
            foo = auth_request.random_key

    def test_pass_arbitrary_parameters_on_pair(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'pairings/create':(
                {'status':'200'},
                '{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}'
                )
            })
        pairing = api.pair('awkward turtle', 'some user', test_param='42')

        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(api.client.last_called_data['pairing_phrase'], 'awkward turtle')
        self.assertEqual(api.client.last_called_data['test_param'], '42')

    def test_pass_arbitrary_parameters_on_authenticate(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate':(
                {'status':'200'},
                '{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}'
                )
            })
        auth_request = api.authenticate('1', 'test terminal', test_param='42')
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(api.client.last_called_data['pairing_id'], '1')
        self.assertEqual(api.client.last_called_data['terminal_name'], 'test terminal')
        self.assertEqual(api.client.last_called_data['test_param'], '42')

    def test_access_arbitrary_keys_in_pairing_status(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'pairings/1':(
                {'status':'200'},
                '{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}, "random_key":"84"}'
                )
            })
        pairing = api.get_pairing_status('1')
        self.assertEqual(api.client.last_called_method, 'GET')

        self.assertEqual(pairing.id, '1')
        self.assertEqual(pairing.user_name, 'some user')
        self.assertEqual(pairing.user_id, '1')
        self.assertTrue(pairing.enabled)

        self.assertEqual(pairing.random_key, "84")

    def test_access_arbitrary_keys_in_authentication_status(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/1':(
                {'status':'200'},
                '{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}, "random_key":"84"}'
                )
            })
        auth_request = api.get_authentication_status('1')
        self.assertEqual(api.client.last_called_method, 'GET')
        self.assertEqual(auth_request.id, '1')
        self.assertFalse(auth_request.pending, False)
        self.assertTrue(auth_request.granted)
        self.assertFalse(auth_request.automated)
        self.assertEqual(auth_request.reason, 'its a test')
        self.assertEqual(auth_request.terminal_id, '1')
        self.assertEqual(auth_request.terminal_name, 'test terminal')

        self.assertEqual(auth_request.random_key, "84")

    def test_disabled_user_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate':
                ({'status': 409}, json.dumps(
                    {'error_code': 704,
                     'error_message': 'disabled user'}))})
        with self.assertRaises(toopher.UserDisabledError):
            auth_request = api.authenticate_by_user_name('disabled user', 'terminal name')

    def test_unknown_user_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate':
                ({'status': 409}, json.dumps(
                    {'error_code': 705,
                     'error_message': 'unknown user'}))})
        with self.assertRaises(toopher.UserUnknownError):
            auth_request = api.authenticate_by_user_name('unknown user', 'terminal name')

    def test_unknown_terminal_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate':
                ({'status': 409}, json.dumps(
                    {'error_code': 706,
                     'error_message': 'unknown terminal'}))})
        with self.assertRaises(toopher.TerminalUnknownError):
            auth_request = api.authenticate_by_user_name('user', 'unknown terminal name')

    def test_deactivated_pairing_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate':
                ({'status': 409}, json.dumps(
                    {'error_code': 601,
                     'error_message': 'pairing has been deactivated'}))})
        with self.assertRaises(toopher.PairingDeactivatedError):
            auth_request = api.authenticate_by_user_name('user', 'terminal name')

    def test_unauthorized_pairing_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate':
                ({'status': 409}, json.dumps(
                    {'error_code': 601,
                     'error_message': 'pairing has not been authorized'}))})
        with self.assertRaises(toopher.PairingDeactivatedError):
            auth_request = api.authenticate_by_user_name('user', 'terminal name')

class ddict(dict):
    def __getitem__(self, key):
        try:
            value = super(ddict, self).__getitem__(key)
            return value
        except KeyError as e:
            return ddict()

class AuthenticationStatusTests(unittest.TestCase):
    def test_nonzero_when_granted(self):
        response = ddict()
        response['granted'] = True
        allowed = toopher.AuthenticationStatus(response)
        self.assertTrue(allowed)

        response['granted'] = False
        denied = toopher.AuthenticationStatus(response)
        self.assertFalse(denied)

class PairingStatusTests(unittest.TestCase):
    def test_incomplete_response_raises_exception(self):
        response = {'key': 'value'}
        with self.assertRaises(toopher.ToopherApiError):
            toopher.PairingStatus(response)

    def test_nonzero_when_granted(self):
        response = ddict()
        response['enabled'] = True
        allowed = toopher.PairingStatus(response)
        self.assertTrue(allowed)

        response['enabled'] = False
        denied = toopher.PairingStatus(response)
        self.assertFalse(denied)

def main():
    unittest.main()

if __name__ == '__main__':
    main()

