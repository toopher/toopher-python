import json
import toopher
import requests
import unittest
import time

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

class ToopherIframeTests(unittest.TestCase):
    request_token = 's9s7vsb'

    def setUp(self):
        self.iframe_api = toopher.ToopherIframe('abcdefg', 'hijklmnop')
        self.iframe_api.client.nonce = '12345678'
        self.old_time = time.time
        time.time = lambda:1000

    def tearDown(self):
        time.time = self.old_time

    def test_validate_good_signature_is_successful(self):
        data = {
                'foo':'bar',
                'timestamp':'1000',
                'session_token':ToopherIframeTests.request_token,
                'toopher_sig':'6d2c7GlQssGmeYYGpcf+V/kirOI='
                }
        try:
            self.iframe_api.validate(data, ToopherIframeTests.request_token)
        except toopher.SignatureValidationError:
            self.fail()
    
    def test_get_pair_uri(self):
        expected = 'https://api.toopher.test/v1/web/pair?username=jdoe&reset_email=jdoe%40example.com&expires=1100&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=UGlgBEUF6UZEhYPxevJeagqy6D4%3D'
        self.assertEqual(expected, self.iframe_api.pair_uri('jdoe', 'jdoe@example.com'))

    def test_get_login_uri(self):
        expected = 'https://api.toopher.test/v1/web/auth?username=jdoe&automation_allowed=True&reset_email=jdoe%40example.com&session_token=s9s7vsb&v=2&requester_metadata=None&challenge_required=False&expires=1100&action_name=Log+In&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=bpgdxhHLDwpYsbru%2Bnz2p9pFlr4%3D'
        self.assertEqual(expected, self.iframe_api.login_uri('jdoe', 'jdoe@example.com', ToopherIframeTests.request_token))


class ToopherTests(unittest.TestCase):
    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    def test_constructor(self):
        def fn():
            api = toopher.ToopherApi()
        self.assertRaises(TypeError, fn)

        api = toopher.ToopherApi('key', 'secret')

    def test_version_number_in_library(self):
        major, minor, patch = toopher.VERSION.split('.')
        self.assertTrue(int(major) >= 1)
        self.assertTrue(int(minor) >= 0)
        self.assertTrue(int(patch) >= 0)

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
            'pairings/create': (200,
                '{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}'
                )
            })
        pairing = api.pair('awkward turtle', 'some user')

        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(api.client.last_called_data['pairing_phrase'], 'awkward turtle')

        def fn():
            self.assertEqual(api.client.last_called_data['test_param'], ['42'])
        self.assertRaises(KeyError, fn)

    def test_pairing_status(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'pairings/1': (200,
                '{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}'
                )
            })
        pairing = api.get_pairing_status('1')
        self.assertEqual(api.client.last_called_method, 'GET')

        self.assertEqual(pairing.id, '1')
        self.assertEqual(pairing.user_name, 'some user')
        self.assertEqual(pairing.user_id, '1')
        self.assertTrue(pairing.enabled)

        def fn():
            foo = pairing.random_key
        self.assertRaises(AttributeError, fn)

    def test_create_authentication_request(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate': (200,
                '{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}'
                )
            })
        auth_request = api.authenticate('1', 'test terminal')
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(api.client.last_called_data['pairing_id'], '1')
        self.assertEqual(api.client.last_called_data['terminal_name'], 'test terminal')

        def fn():
            self.assertEqual(api.client.last_called_data['test_param'], '42')
        self.assertRaises(KeyError, fn)

        api.authenticate('pairing_id', 'terminal_name', 'action_name')

        last_called_data = api.client.last_called_data
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(last_called_data['pairing_id'], 'pairing_id')
        self.assertEqual(last_called_data['terminal_name'], 'terminal_name')
        self.assertEqual(last_called_data['action_name'], 'action_name')

    def test_authentication_status(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/1': (200,
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

        def fn():
            foo = auth_request.random_key
        self.assertRaises(AttributeError, fn)

    def test_pass_arbitrary_parameters_on_pair(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'pairings/create': (200,
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
            'authentication_requests/initiate': (200,
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
            'pairings/1': (200,
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
            'authentication_requests/1': (200,
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

    def test_pair_sms(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'pairings/create/sms': (200,
                json.dumps({'id': 'id',
                            'enabled': True,
                            'user': {'id': 'id', 'name': 'name'}}))})

        api.pair_sms('phone_number', 'user_name')
        last_called_data = api.client.last_called_data
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(last_called_data['phone_number'], 'phone_number')
        self.assertEqual(last_called_data['user_name'], 'user_name')

        api.pair_sms('phone_number', 'user_name', 'phone_country')
        last_called_data = api.client.last_called_data
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(last_called_data['phone_number'], 'phone_number')
        self.assertEqual(last_called_data['user_name'], 'user_name')
        self.assertEqual(last_called_data['phone_country'], 'phone_country')

    def test_authenticate_with_otp(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/id/otp_auth': (200,
                json.dumps({'id': 'id',
                            'pending': False,
                            'granted': False,
                            'automated': False,
                            'reason': 'it is a test',
                            'terminal': {'id': 'id', 'name': 'name'}}))})

        api.authenticate_with_otp('id', 'otp')
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(api.client.last_called_data['otp'], 'otp')

    def test_unrecognized_error_still_raises_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({'error_code': 42,
                            'error_message': 'what'}))})

        def fn():
            api.authenticate_by_user_name('user_name', 'terminal_name')
        self.assertRaises(toopher.ToopherApiError, fn)

class ZeroStorageTests(unittest.TestCase):
    def test_create_user_terminal(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({'user_terminals/create': (200, '{}')})

        api.create_user_terminal('user_name', 'terminal_name', 'requester_terminal_id')

        last_called_data = api.client.last_called_data
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertEqual(last_called_data['user_name'], 'user_name')
        self.assertEqual(last_called_data['name'], 'terminal_name')
        self.assertEqual(last_called_data['name_extra'], 'requester_terminal_id')

    def test_enable_toopher_for_user(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'users': (200, json.dumps([{'id': 'user_id', 'name': 'user_name'}])),
            'users/user_id': (200, json.dumps({'name': 'user_name'}))})

        api.set_toopher_enabled_for_user('user_name', True)
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertFalse(api.client.last_called_data['disable_toopher_auth'])

        api.set_toopher_enabled_for_user('user_name', False)
        self.assertEqual(api.client.last_called_method, 'POST')
        self.assertTrue(api.client.last_called_data['disable_toopher_auth'])

    def test_enable_toopher_multiple_users(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({'users': (200,
            json.dumps([{'name': 'first user'}, {'name': 'second user'}]))})

        def fn():
            api.set_toopher_enabled_for_user('multiple users', True)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_enable_toopher_no_users(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({'users': (200, '[]')})

        def fn():
            api.set_toopher_enabled_for_user('no users', True)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_disabled_user_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({'error_code': 704,
                            'error_message': 'disabled user'}))})

        def fn():
            auth_request = api.authenticate_by_user_name('disabled user', 'terminal name')
        self.assertRaises(toopher.UserDisabledError, fn)

    def test_unknown_user_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({'error_code': 705,
                             'error_message': 'unknown user'}))})

        def fn():
            auth_request = api.authenticate_by_user_name('unknown user', 'terminal name')
        self.assertRaises(toopher.UserUnknownError, fn)

    def test_unknown_terminal_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({'error_code': 706,
                            'error_message': 'unknown terminal'}))})

        def fn():
            auth_request = api.authenticate_by_user_name('user', 'unknown terminal name')
        self.assertRaises(toopher.TerminalUnknownError, fn)

    def test_deactivated_pairing_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({'error_code': 601,
                            'error_message': 'Pairing has been deactivated'}))})

        def fn():
            auth_request = api.authenticate_by_user_name('user', 'terminal name')
        self.assertRaises(toopher.PairingDeactivatedError, fn)

    def test_unauthorized_pairing_raises_correct_error(self):
        api = toopher.ToopherApi('key', 'secret')
        api.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({'error_code': 601,
                            'error_message': 'Pairing has not been authorized'}))})

        def fn():
            auth_request = api.authenticate_by_user_name('user', 'terminal name')
        self.assertRaises(toopher.PairingDeactivatedError, fn)

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
        def fn():
            toopher.PairingStatus(response)
        self.assertRaises(toopher.ToopherApiError, fn)

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

