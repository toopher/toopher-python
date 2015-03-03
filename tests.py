import json
import pickle
import toopher
import requests
import unittest
import uuid
import time
import urllib

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
        time.time = lambda: 1000

    def tearDown(self):
        time.time = self.old_time

    def _get_auth_request_postback_data_as_dict(self):
        return {
            'id': '1',
            'pending': 'false',
            'granted': 'true',
            'automated': 'false',
            'reason': 'it is a test',
            'reason_code': '100',
            'terminal_id': '1',
            'terminal_name': 'terminal name',
            'terminal_requester_specified_id': 'requester specified id',
            'pairing_user_id': '1',
            'user_name': 'user name',
            'user_toopher_authentication_enabled': 'true',
            'action_id': '1',
            'action_name': 'action name',
            'toopher_sig': 's+fYUtChrNMjES5Xa+755H7BQKE=',
            'session_token': ToopherIframeTests.request_token,
            'timestamp': '1000',
            'resource_type': 'authentication_request'
        }

    def _get_urlencoded_auth_request_postback_data(self, auth_request_data = None):
        data = auth_request_data if auth_request_data else self._get_auth_request_postback_data_as_dict()
        return {'toopher_iframe_data': urllib.urlencode(data)}

    def _get_urlencoded_pairing_postback_data(self):
        return {'toopher_iframe_data': urllib.urlencode({
            'id': '1',
            'enabled': 'true',
            'pending': 'false',
            'pairing_user_id': '1',
            'user_name': 'user name',
            'user_toopher_authentication_enabled': 'true',
            'toopher_sig': 'ucwKhkPpN4VxNbx3dMypWzi4tBg=',
            'session_token': ToopherIframeTests.request_token,
            'timestamp': '1000',
            'resource_type': 'pairing'
        })}

    def _get_urlencoded_user_postback_data(self):
        return {'toopher_iframe_data': urllib.urlencode({
            'id': '1',
            'name': 'user name',
            'toopher_authentication_enabled': 'true',
            'toopher_sig': 'RszgG9QE1rF9t7DVTGg+1I25yHM=',
            'session_token': ToopherIframeTests.request_token,
            'timestamp': '1000',
            'resource_type': 'requester_user'
        })}

    def test_process_postback_good_signature_returns_authentication_request(self):
        auth_request = self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(), ToopherIframeTests.request_token)
        self.assertEqual(type(auth_request), toopher.AuthenticationRequest)

    def test_process_postback_good_signature_returns_pairing(self):
        pairing = self.iframe_api.process_postback(self._get_urlencoded_pairing_postback_data(), ToopherIframeTests.request_token)
        self.assertEqual(type(pairing), toopher.Pairing)

    def test_process_postback_good_signature_returns_user(self):
        user = self.iframe_api.process_postback(self._get_urlencoded_user_postback_data(), ToopherIframeTests.request_token)
        self.assertEqual(type(user), toopher.User)

    def test_process_postback_bad_signature_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['toopher_sig'] = 'invalid'
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('SignatureValidationError was not raised for bad signature')
        except toopher.SignatureValidationError as e:
            self.assertEqual(e.message, 'Computed signature does not match submitted signature: {0} vs {1}'.format(self._get_auth_request_postback_data_as_dict()['toopher_sig'], data['toopher_sig']))

    def test_process_postback_expired_signature_fails(self):
        data = self._get_urlencoded_auth_request_postback_data()
        time.time = lambda: 2000
        try:
            self.iframe_api.process_postback(data, ToopherIframeTests.request_token)
            self.fail('SignatureValidationError was not raised for expired signature')
        except toopher.SignatureValidationError as e:
            self.assertEqual(e.message, 'TTL expired')

    def test_process_postback_missing_signature_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        del data['toopher_sig']
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('SignatureValidationError was not raised for missing toopher_sig')
        except toopher.SignatureValidationError as e:
            self.assertEqual(e.message, 'Missing required keys: toopher_sig')

    def test_process_postback_missing_timestamp_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        del data['timestamp']
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('SignatureValidationError was not raised for missing timestamp')
        except toopher.SignatureValidationError as e:
            self.assertEqual(e.message, 'Missing required keys: timestamp')

    def test_process_postback_missing_session_token_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        del data['session_token']
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('SignatureValidationError was not raised for missing session_token')
        except toopher.SignatureValidationError as e:
            self.assertEqual(e.message, 'Missing required keys: session_token')

    def test_process_postback_invalid_session_token_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['session_token'] = 'invalid token'
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('SignatureValidationError was not raised for invalid session_token')
        except toopher.SignatureValidationError as e:
            self.assertEqual(e.message, 'Session token does not match expected value!')

    def test_process_postback_with_704_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['error_code'] = 704
        data['error_message'] = 'The specified user has disabled Toopher authentication.'
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('UserDisabledError was not raised for error code 704')
        except toopher.UserDisabledError as e:
            self.assertEqual(e.message, 'The specified user has disabled Toopher authentication.')

    def test_process_postback_with_705_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['error_code'] = 705
        data['error_message'] = 'No matching user exists'
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('UserUnknownError was not raised for error code 705')
        except toopher.UserUnknownError as e:
            self.assertEqual(e.message, 'No matching user exists')

    def test_process_postback_with_706_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['error_code'] = 706
        data['error_message'] = 'No matching terminal exists'
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('TerminalUnknownError was not raised for error code 706')
        except toopher.TerminalUnknownError as e:
            self.assertEqual(e.message, 'No matching terminal exists')

    def test_process_postback_with_707_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['error_code'] = 707
        data['error_message'] = 'Not allowed: This pairing has been deactivated.'
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('PairingDeactivatedError was not raised for error code 707')
        except toopher.PairingDeactivatedError as e:
            self.assertEqual(e.message, 'Not allowed: This pairing has been deactivated.')

    def test_is_postback_granted_is_true_with_auth_request_granted(self):
        data = self._get_urlencoded_auth_request_postback_data()
        postback_granted = self.iframe_api.is_postback_granted(data, ToopherIframeTests.request_token)
        self.assertTrue(postback_granted, 'Postback should have been granted with AuthentiationRequest.granted = True')

    def test_is_postback_granted_is_false_with_auth_request_not_granted(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['granted'] = 'false'
        data['toopher_sig'] = 'nADNKdly9zA2IpczD6gvDumM48I='
        postback_granted = self.iframe_api.is_postback_granted(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
        self.assertFalse(postback_granted, 'Postback should not have been granted with AuthenticationRequest not granted')

    def test_is_postback_granted_raises_error_when_pairing_is_returned(self):
        try:
            self.iframe_api.is_postback_granted(self._get_urlencoded_pairing_postback_data(), ToopherIframeTests.request_token)
            self.fail('ToopherApiError was not raised when postback returned Pairing object')
        except toopher.ToopherApiError as e:
            self.assertEqual(e.message, 'The postback did not return an AuthenticationRequest')

    def test_is_postback_granted_raises_error_when_user_is_returned(self):
        try:
            self.iframe_api.is_postback_granted(self._get_urlencoded_user_postback_data(), ToopherIframeTests.request_token)
            self.fail('ToopherApiError was nont raised when postback returned User object')
        except toopher.ToopherApiError as e:
            self.assertEqual(e.message, 'The postback did not return an AuthenticationRequest')

    def test_get_user_management_url(self):
        expected = 'https://api.toopher.test/v1/web/manage_user?username=jdoe&reset_email=jdoe%40example.com&expires=1300&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=NjwH5yWPE2CCJL8v%2FMNknL%2BeTpE%3D'
        self.assertEqual(expected, self.iframe_api.get_user_management_url('jdoe', 'jdoe@example.com'))

    def test_get_authentication_url(self):
        expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=jdoe%40example.com&session_token=s9s7vsb&expires=1300&action_name=Log+In&requester_metadata=None&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=YN%2BkKNTaoypsB37fsjvMS8vsG5A%3D'
        self.assertEqual(expected, self.iframe_api.get_authentication_url('jdoe', 'jdoe@example.com', ToopherIframeTests.request_token))

    def test_get_authentication_url_without_inline_pairing(self):
        expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=jdoe%40example.com&session_token=s9s7vsb&allow_inline_pairing=False&expires=1300&action_name=Log+In&requester_metadata=None&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=Vt%2B%2FKZzF%2BqtLswtVUDWCq5Y97IM%3D'
        self.assertEqual(expected, self.iframe_api.get_authentication_url('jdoe', 'jdoe@example.com', ToopherIframeTests.request_token, allow_inline_pairing=False))


class ToopherTests(unittest.TestCase):
    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret')
        self.id = str(uuid.uuid4())
        self.name = 'name'
        self.user = {
            'id': str(uuid.uuid4()),
            'name': 'user_name',
            'toopher_authentication_enabled': True
        }
        self.user_id = self.user['id']
        self.user_name = self.user['name']
        self.reason = 'it is a test'
        self.reason_code = '0'
        self.terminal = {
            'id': str(uuid.uuid4()),
            'name': 'terminal_name',
            'requester_specified_id': 'requester_specified_id',
            'user' : self.user
        }
        self.terminal_id = self.terminal['id']
        self.terminal_name = self.terminal['name']
        self.requester_specified_id = self.terminal['requester_specified_id']
        self.action = {
            'id': str(uuid.uuid4()),
            'name': 'action_name'
        }
        self.action_id = self.action['id']
        self.action_name = self.action['name']

    def test_constructor(self):
        def fn():
            api = toopher.ToopherApi()
        self.assertRaises(TypeError, fn)

    def test_version_number_in_library(self):
        major, minor, patch = toopher.VERSION.split('.')
        self.assertTrue(int(major) >= 1)
        self.assertTrue(int(minor) >= 0)
        self.assertTrue(int(patch) >= 0)

    def test_version_number_in_setup(self):
        ''' Ensure that the setup.py file has the same version number as the toopher/__init__.py file '''
        for line in open('setup.py'):
            if 'version' in line:
                # in setup.py the version is written as "version='1.0.6'," so we need to remove version=' and ',
                version_number = line.strip().replace("version='", "").replace("',", "")
                self.assertEqual(version_number, toopher.VERSION)

    def test_create_user(self):
        self.api.advanced.raw.client = HttpClientMock({
            'users/create': (200,
                json.dumps({
                    'id': self.id,
                    'name': self.name,
                    'toopher_authentication_enabled': True
                })
            )
        })
        user = self.api.advanced.users.create(self.name)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(user.id, self.id)
        self.assertEqual(user.name, self.name)
        self.assertTrue(user.toopher_authentication_enabled)

    def test_get_user_by_id(self):
        self.api.advanced.raw.client = HttpClientMock({
            'users/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'name': self.name,
                    'toopher_authentication_enabled': True
                })
            )
        })
        user = self.api.advanced.users.get_by_id(self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(user.id, self.id)
        self.assertEqual(user.name, self.name)
        self.assertTrue(user.toopher_authentication_enabled)

    def test_get_user_by_name(self):
        self.api.advanced.raw.client = HttpClientMock({
            'users': (200,
                json.dumps([{
                    'id': self.user_id,
                    'name': self.user_name,
                    'toopher_authentication_enabled': True
                }])
            )
        })
        user = self.api.advanced.users.get_by_name(self.user_name)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(user.id, self.user_id)
        self.assertEqual(user.name, self.user_name)
        self.assertTrue(user.toopher_authentication_enabled)

    def test_get_multiple_users_by_name_raises_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'users': (200,
                json.dumps([{
                    'id': self.user_id,
                    'name': self.user_name,
                    'toopher_authentication_enabled': True
                }, {
                    'id': '2',
                    'name': self.user_name,
                    'toopher_authentication_enabled': True
                }])
            )
        })

        def fn():
            self.api.advanced.users.get_by_name(self.user_name)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_get_user_by_name_does_not_exist_raises_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'users': (200, '[]')
        })

        def fn():
            self.api.advanced.users.get_by_name(self.user_name)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_create_pairing(self):
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/create': (200,
                json.dumps({
                    'id': self.id,
                    'enabled': True,
                    'pending': True,
                    'user': self.user
                })
            )
        })
        self.api.pair(self.user_name, 'awkward turtle')
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['pairing_phrase'], 'awkward turtle')

        def fn():
            self.assertEqual(self.api.advanced.raw.client.last_called_data['test_param'], ['42'])
        self.assertRaises(KeyError, fn)

    def test_pairing(self):
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'enabled': True,
                    'pending': True,
                    'user': self.user
                })
            )
        })
        pairing = self.api.advanced.pairings.get_by_id(self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(pairing.id, self.id)
        self.assertEqual(pairing.user.name, self.user_name)
        self.assertEqual(pairing.user.id, self.user_id)
        self.assertTrue(pairing.user.toopher_authentication_enabled)
        self.assertTrue(pairing.enabled)
        self.assertTrue(pairing.pending)

        def fn():
            foo = pairing.random_key
        self.assertRaises(AttributeError, fn)

    def test_create_authentication_request(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (200,
                json.dumps({
                    'id': self.id,
                    'pending': False,
                    'granted': True,
                    'automated': False,
                    'reason': self.reason,
                    'reason_code': self.reason_code,
                    'terminal': self.terminal,
                    'user': self.user,
                    'action': self.action
                })
            )
        })
        self.api.authenticate(self.id, self.terminal_name)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['pairing_id'], self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_data['terminal_name'], self.terminal_name)

        def fn():
            self.assertEqual(self.api.advanced.raw.client.last_called_data['test_param'], '42')
        self.assertRaises(KeyError, fn)

        self.api.authenticate(self.id, self.terminal_name, action_name=self.action_name)
        last_called_data = self.api.advanced.raw.client.last_called_data
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(last_called_data['pairing_id'], self.id)
        self.assertEqual(last_called_data['terminal_name'], self.terminal_name)
        self.assertEqual(last_called_data['action_name'], self.action_name)

    def test_get_authentication_request_by_id(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'pending': False,
                    'granted': True,
                    'automated': False,
                    'reason': self.reason,
                    'reason_code': self.reason_code,
                    'terminal': self.terminal,
                    'user': self.user,
                    'action': self.action
                })
            )
        })
        auth_request = self.api.advanced.authentication_requests.get_by_id(self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(auth_request.id, self.id)
        self.assertFalse(auth_request.pending)
        self.assertTrue(auth_request.granted)
        self.assertFalse(auth_request.automated)
        self.assertEqual(auth_request.reason, self.reason)
        self.assertEqual(auth_request.reason_code, self.reason_code)
        self.assertEqual(auth_request.terminal.id, self.terminal_id)
        self.assertEqual(auth_request.terminal.name, self.terminal_name)
        self.assertEqual(auth_request.action.id, self.action_id)
        self.assertEqual(auth_request.action.name, self.action_name)

        def fn():
            foo = auth_request.random_key
        self.assertRaises(AttributeError, fn)

    def test_pass_arbitrary_parameters_on_pair(self):
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/create': (200,
                json.dumps({
                    'id': self.id,
                    'enabled': True,
                    'pending': True,
                    'user': self.user
                })
            )
        })
        self.api.pair(self.user_name, 'awkward turtle', test_param='42')
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['pairing_phrase'], 'awkward turtle')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['test_param'], '42')

    def test_pass_arbitrary_parameters_on_authenticate(self):
        api = toopher.ToopherApi('key', 'secret')
        api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (200,
                json.dumps({
                    'id': self.id,
                    'pending': False,
                    'granted': True,
                    'automated': False,
                    'reason': self.reason,
                    'reason_code': self.reason_code,
                    'terminal': self.terminal,
                    'user': self.user,
                    'action': self.action
                })
            )
        })
        api.authenticate(self.id, self.terminal_name, test_param='42')
        self.assertEqual(api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(api.advanced.raw.client.last_called_data['pairing_id'], self.id)
        self.assertEqual(api.advanced.raw.client.last_called_data['terminal_name'], self.terminal_name)
        self.assertEqual(api.advanced.raw.client.last_called_data['test_param'], '42')

    def test_access_arbitrary_keys_in_pairing(self):
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'enabled': True,
                    'pending': True,
                    'user': self.user,
                    'random_key': '84'
                })
            )
        })
        pairing = self.api.advanced.pairings.get_by_id(self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(pairing.id, self.id)
        self.assertEqual(pairing.user.name, self.user_name)
        self.assertEqual(pairing.user.id, self.user_id)
        self.assertTrue(pairing.user.toopher_authentication_enabled)
        self.assertTrue(pairing.enabled)
        self.assertEqual(pairing.random_key, '84')

    def test_access_arbitrary_keys_in_authentication_request(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'pending': False,
                    'granted': True,
                    'automated': False,
                    'reason': self.reason,
                    'reason_code': self.reason_code,
                    'terminal': self.terminal,
                    'user': self.user,
                    'action': self.action,
                    'random_key': '84'
                })
            )
        })
        auth_request = self.api.advanced.authentication_requests.get_by_id(self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(auth_request.id, self.id)
        self.assertFalse(auth_request.pending)
        self.assertTrue(auth_request.granted)
        self.assertFalse(auth_request.automated)
        self.assertEqual(auth_request.reason, self.reason)
        self.assertEqual(auth_request.reason_code, self.reason_code)
        self.assertEqual(auth_request.terminal.id, self.terminal_id)
        self.assertEqual(auth_request.terminal.name, self.terminal_name)
        self.assertEqual(auth_request.user.id, self.user_id)
        self.assertEqual(auth_request.user.name, self.user_name)
        self.assertEqual(auth_request.action.id, self.action_id)
        self.assertEqual(auth_request.action.name, self.action_name)
        self.assertEqual(auth_request.random_key, '84')

    def test_pair_qr(self):
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/create/qr': (200,
                json.dumps({
                    'id': 'id',
                    'enabled': True,
                    'pending': True,
                    'user': self.user
                })
            )
        })
        self.api.pair(self.user_name)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['user_name'], self.user_name)

    def test_pair_sms(self):
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/create/sms': (200,
                json.dumps({
                    'id': self.id,
                    'enabled': True,
                    'pending': True,
                    'user': self.user
                })
            )
        })
        self.api.pair(self.user_name, '555-555-5555')
        last_called_data = self.api.advanced.raw.client.last_called_data
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(last_called_data['phone_number'], '555-555-5555')
        self.assertEqual(last_called_data['user_name'], self.user_name)

        self.api.pair(self.user_name, '555-555-5555', phone_country='1')
        last_called_data = self.api.advanced.raw.client.last_called_data
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(last_called_data['phone_number'], '555-555-5555')
        self.assertEqual(last_called_data['user_name'], self.user_name)
        self.assertEqual(last_called_data['phone_country'], '1')

    def test_bad_response_raises_correct_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (200,
                'lol if you think this is json')})

        def fn():
            self.api.authenticate(self.user_name, requester_specified_id=self.requester_specified_id)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_unrecognized_error_still_raises_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({
                    'error_code': 42,
                    'error_message': 'what'
                })
            )
        })

        def fn():
            self.api.authenticate(self.user_name, requester_specified_id=self.requester_specified_id)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_create_user_terminal(self):
        self.api.advanced.raw.client = HttpClientMock({
            'user_terminals/create': (200,
                json.dumps({
                    'id': self.id,
                    'name': self.terminal_name,
                    'requester_specified_id': self.requester_specified_id,
                    'user': self.user
                })
            )
        })
        user_terminal = self.api.advanced.user_terminals.create(self.user_name, self.terminal_name, self.requester_specified_id)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(user_terminal.id, self.id)
        self.assertEqual(user_terminal.user.name, self.user_name)
        self.assertEqual(user_terminal.user.id, self.user_id)
        self.assertEqual(user_terminal.name, self.terminal_name)
        self.assertEqual(user_terminal.requester_specified_id, self.requester_specified_id)

    def test_get_user_terminal_by_id(self):
        self.api.advanced.raw.client = HttpClientMock({
            'user_terminals/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'name': self.terminal_name,
                    'requester_specified_id': self.requester_specified_id,
                    'user': self.user
                })
            )
        })
        user_terminal = self.api.advanced.user_terminals.get_by_id(self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(user_terminal.id, self.id)
        self.assertEqual(user_terminal.name, self.terminal_name)
        self.assertEqual(user_terminal.requester_specified_id, self.requester_specified_id)
        self.assertEqual(user_terminal.user.name, self.user_name)
        self.assertEqual(user_terminal.user.id, self.user_id)

    def test_raw_get(self):
        self.api.advanced.raw.client = HttpClientMock({
            'pairings/{0}'.format(self.id): (200,
                json.dumps({
                    'id': self.id,
                    'enabled': True,
                    'user': self.user
                })
            )
        })
        result = self.api.advanced.raw.get('/pairings/{0}'.format(self.id))
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'GET')
        self.assertEqual(result['id'], self.id)
        self.assertEqual(result['user']['name'], self.user_name)
        self.assertEqual(result['user']['id'], self.user_id)
        self.assertTrue(result['enabled'])

    def test_raw_post(self):
        self.api.advanced.raw.client = HttpClientMock({
            'user_terminals/create': (200,
                json.dumps({
                  'id': self.id,
                  'name': self.terminal_name,
                  'requester_specified_id': self.requester_specified_id,
                  'user': self.user
                })
            )
        })
        result = self.api.advanced.raw.post('/user_terminals/create',
                               name='terminal_name',
                               requester_specified_id='requester_specified_id',
                               user_name='user_name')
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(result['id'], self.id)
        self.assertEqual(result['user']['name'], self.user_name)
        self.assertEqual(result['user']['id'], self.user_id)
        self.assertEqual(result['name'], self.terminal_name)
        self.assertEqual(result['requester_specified_id'], self.requester_specified_id)

    def test_disabled_user_raises_correct_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({
                    'error_code': 704,
                    'error_message': 'disabled user'
                })
            )
        })

        def fn():
            auth_request = self.api.authenticate('disabled user', 'terminal name')
        self.assertRaises(toopher.UserDisabledError, fn)

    def test_unknown_user_raises_correct_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({
                    'error_code': 705,
                    'error_message': 'unknown user'
                })
            )
        })

        def fn():
            auth_request = self.api.authenticate('unknown user', 'terminal name')
        self.assertRaises(toopher.UserUnknownError, fn)

    def test_unknown_terminal_raises_correct_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({
                    'error_code': 706,
                    'error_message': 'unknown terminal'
                })
            )
        })

        def fn():
            auth_request = self.api.authenticate(self.user_name, 'unknown terminal name')
        self.assertRaises(toopher.TerminalUnknownError, fn)

    def test_deactivated_pairing_raises_correct_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({
                    'error_code': 707,
                    'error_message': 'Pairing has been deactivated'
                })
            )
        })

        def fn():
            auth_request = self.api.authenticate(self.user_name, requester_specified_id=self.requester_specified_id)
        self.assertRaises(toopher.PairingDeactivatedError, fn)

    def test_unauthorized_pairing_raises_correct_error(self):
        self.api.advanced.raw.client = HttpClientMock({
            'authentication_requests/initiate': (409,
                json.dumps({
                    'error_code': 601,
                    'error_message': 'Pairing has not been authorized'
                })
            )
        })

        def fn():
            auth_request = self.api.authenticate(self.user_name, requester_specified_id=self.requester_specified_id)
        self.assertRaises(toopher.PairingDeactivatedError, fn)

class ToopherBaseTests(unittest.TestCase):
    def test_pickling_and_unpickling(self):
        response = {
            'id': str(uuid.uuid4()),
            'enabled': True,
            'pending': True,
            'user': {
                'id': str(uuid.uuid4()),
                'name': 'user_name',
                'toopher_authentication_enabled': True
            }
        }
        pairing = toopher.Pairing(response, toopher.ToopherApi('key', 'secret'))
        try:
            pickled_pairing = pickle.loads(pickle.dumps(pairing))
        except RuntimeError as e:
            self.fail('Unable to unpickle a pickled object: %s' % e)

        self.assertEqual(pairing.id, pickled_pairing.id)
        self.assertEqual(pairing.user.id, pickled_pairing.user.id)
        self.assertEqual(pairing.user.name, pickled_pairing.user.name)
        self.assertTrue(pickled_pairing.enabled)
        self.assertTrue(pickled_pairing.pending)
        self.assertEqual(dir(pairing), dir(pickled_pairing))

class ddict(dict):
    def __getitem__(self, key):
        try:
            value = super(ddict, self).__getitem__(key)
            return value
        except KeyError as e:
            return ddict()


class AuthenticationRequestTests(unittest.TestCase):
    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret')
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
        

class PairingTests(unittest.TestCase):
    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret')
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


class UserTests(unittest.TestCase):
    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret')
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
        try:
            user.reset()
        except toopher.ToopherApiError as e:
            self.fail('pairing.email_reset_link() returned a status code of >= 400: %s' % e)

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


def main():
    unittest.main()

if __name__ == '__main__':
    main()
