import unittest
import time
import urllib
import toopher
import logging

class ToopherIframeTests(unittest.TestCase):
    logging.disable(logging.CRITICAL)

    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    request_token = 's9s7vsb'

    def setUp(self):
        self.iframe_api = toopher.ToopherIframe('abcdefg', 'hijklmnop', 'https://api.toopher.test/v1')
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

    def test_process_postback_bad_resource_type_raises_error(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['resource_type'] = 'invalid'
        data['toopher_sig'] = 'xEY+oOtJcdMsmTLp6eOy9isO/xQ='
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('ToopherApiError was not raise for invalid postback resource type')
        except toopher.ToopherApiError as e:
            self.assertEqual(e.message, 'The postback resource type is not valid: invalid')

    def test_process_postback_with_704_fails(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['error_code'] = 704
        data['error_message'] = 'The specified user has disabled Toopher authentication.'
        try:
            self.iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
            self.fail('UserDisabledError was not raised for error code 704')
        except toopher.UserDisabledError as e:
            self.assertEqual(e.message, 'The specified user has disabled Toopher authentication.')

    def test_process_postback_with_bad_secret_raises_error(self):
        iframe_api = toopher.ToopherIframe('abcdefg', 1, 'https://api.toopher.test/v1')
        try:
            iframe_api.process_postback(self._get_urlencoded_auth_request_postback_data(), ToopherIframeTests.request_token)
            self.fail('SignatureValidationError was not raised while calculating signature with bad secret')
        except toopher.SignatureValidationError as e:
            self.assertEqual(e.message, "Error while calculating signature: 'int' object has no attribute 'encode'")

    def test_is_authentication_granted_is_true_with_auth_request_granted(self):
        data = self._get_urlencoded_auth_request_postback_data()
        authentication_granted = self.iframe_api.is_authentication_granted(data, ToopherIframeTests.request_token)
        self.assertTrue(authentication_granted, 'Postback should have been granted with AuthentiationRequest.granted = True')

    def test_is_authentication_granted_is_false_with_auth_request_not_granted(self):
        data = self._get_auth_request_postback_data_as_dict()
        data['granted'] = 'false'
        data['toopher_sig'] = 'nADNKdly9zA2IpczD6gvDumM48I='
        authentication_granted = self.iframe_api.is_authentication_granted(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
        self.assertFalse(authentication_granted, 'Postback should not have been granted with AuthenticationRequest not granted')

    def test_is_authentication_granted_returns_false_when_pairing_is_returned(self):
        authentication_granted = self.iframe_api.is_authentication_granted(self._get_urlencoded_pairing_postback_data(), ToopherIframeTests.request_token)
        self.assertFalse(authentication_granted)

    def test_is_authentication_granted_returns_false_when_user_is_returned(self):
        authentication_granted = self.iframe_api.is_authentication_granted(self._get_urlencoded_user_postback_data(), ToopherIframeTests.request_token)
        self.assertFalse(authentication_granted)

    def test_is_authentication_granted_returns_false_when_missing_keys(self):
        data = self._get_auth_request_postback_data_as_dict()
        del data['id']
        authentication_granted = self.iframe_api.is_authentication_granted(self._get_urlencoded_auth_request_postback_data(data), ToopherIframeTests.request_token)
        self.assertFalse(authentication_granted)

    def test_is_authentication_granted_returns_false_when_process_postback_returns_user(self):
        authentication_granted = self.iframe_api.is_authentication_granted(self._get_urlencoded_user_postback_data(), ToopherIframeTests.request_token)
        self.assertFalse(authentication_granted)

    def test_get_user_management_url(self):
        expected = 'https://api.toopher.test/v1/web/manage_user?username=jdoe&reset_email=jdoe%40example.com&expires=1300&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=NjwH5yWPE2CCJL8v%2FMNknL%2BeTpE%3D'
        self.assertEqual(expected, self.iframe_api.get_user_management_url('jdoe', 'jdoe@example.com'))

    def test_get_user_manage_url_removes_ttl_from_kwargs(self):
        expected = 'https://api.toopher.test/v1/web/manage_user?username=jdoe&reset_email=jdoe%40example.com&expires=1500&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=%2BQrbKZH2NDxURKE9Yjb6wxegeAM%3D'
        url = self.iframe_api.get_user_management_url('jdoe', 'jdoe@example.com', ttl=500)
        self.assertEqual(expected, url)

    def test_get_authentication_url(self):
        expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=jdoe%40example.com&session_token=s9s7vsb&expires=1300&action_name=Log+In&requester_metadata=None&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=YN%2BkKNTaoypsB37fsjvMS8vsG5A%3D'
        self.assertEqual(expected, self.iframe_api.get_authentication_url('jdoe', 'jdoe@example.com', ToopherIframeTests.request_token))

    def test_get_authentication_url_with_optional_args_and_extras(self):
        expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=jdoe%40example.com&session_token=s9s7vsb&allow_inline_pairing=False&expires=1100&action_name=it+is+a+test&automation_allowed=False&requester_metadata=metadata&v=2&challenge_required=True&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=hKogqI%2FgjKXpYIH%2BjNDhRSi22b4%3D'
        self.assertEqual(expected, self.iframe_api.get_authentication_url('jdoe', 'jdoe@example.com', ToopherIframeTests.request_token, 'it is a test', 'metadata', allow_inline_pairing=False, automation_allowed=False, challenge_required=True, ttl=100))

    def test_get_authentication_url_with_extras(self):
        expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=None&session_token=None&allow_inline_pairing=False&expires=1100&action_name=Log+In&automation_allowed=False&requester_metadata=None&v=2&challenge_required=True&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=zdE78ucexk2Y9T5NVRDsf9NvcOI%3D'
        self.assertEqual(expected, self.iframe_api.get_authentication_url('jdoe', allow_inline_pairing=False, automation_allowed=False, challenge_required=True, ttl=100))

    def test_get_authentication_url_removes_ttl_from_kwargs(self):
        expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=jdoe%40example.com&session_token=None&expires=1500&action_name=Log+In&requester_metadata=None&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=EtlblFjm2cbmQHWxwXL0lc3J2pY%3D'
        url = self.iframe_api.get_authentication_url('jdoe', 'jdoe@example.com', ttl=500)
        self.assertEqual(expected, url)

    def test_get_authentication_url_only_username(self):
        expected = 'https://api.toopher.test/v1/web/authenticate?username=jdoe&reset_email=None&session_token=None&expires=1300&action_name=Log+In&requester_metadata=None&v=2&oauth_nonce=12345678&oauth_timestamp=1000&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_consumer_key=abcdefg&oauth_signature=Udj%2BxFeLQgSKzKyntCIOq5mODSs%3D'
        url = self.iframe_api.get_authentication_url('jdoe')
        self.assertEqual(expected, url)