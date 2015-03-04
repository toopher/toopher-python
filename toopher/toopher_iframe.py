from oauthlib import oauth1
import urllib
import urlparse
import hashlib
import hmac
import base64
import time
import logging
from toopher_api import *

DEFAULT_BASE_URL = 'https://api.toopher.com/v1'
DEFAULT_IFRAME_TTL = 300
IFRAME_VERSION = '2'

class SignatureValidationError(ToopherApiError): pass

class ToopherIframe(object):
    logging.basicConfig(format='%(levelname)s: %(message)s')

    def __init__(self, key, secret, api_uri=None):
        self.key = key
        self.secret = secret
        self.client = oauth1.Client(key, client_secret=secret, signature_type=oauth1.SIGNATURE_TYPE_QUERY)
        api_uri = api_uri if api_uri else DEFAULT_BASE_URL
        self.base_uri = api_uri.rstrip('/')

    def get_user_management_url(self, username, reset_email, **kwargs):
        if not 'ttl' in kwargs:
            ttl = DEFAULT_IFRAME_TTL
        else:
            ttl = kwargs.pop('ttl')

        params = {
                'v':IFRAME_VERSION,
                'username':username,
                'reset_email':reset_email
                }
        params.update(kwargs)

        return self._get_oauth_signed_url(self.base_uri + '/web/manage_user', params, ttl)

    def get_authentication_url(self, username, reset_email='None', request_token='None', action_name='Log In', requester_metadata='None', **kwargs):
        if not 'ttl' in kwargs:
            ttl = DEFAULT_IFRAME_TTL
        else:
            ttl = kwargs.pop('ttl')

        params = {
            'v':IFRAME_VERSION,
            'username':username,
            'reset_email':reset_email,
            'action_name':action_name,
            'session_token':request_token,
            'requester_metadata':requester_metadata
        }
        params.update(kwargs)

        return self._get_oauth_signed_url(self.base_uri + '/web/authenticate', params, ttl)

    def process_postback(self, urlencoded_form_data, request_token=None, **kwargs):
        toopher_data = self._urldecode_iframe_data(urlencoded_form_data)

        if 'error_code' in toopher_data:
            error_message = toopher_data['error_message']
            error = error_codes_to_errors[int(toopher_data['error_code'])]
            raise error(error_message)
        else:
            validated_data = self._validate_data(toopher_data, request_token, kwargs)
            toopher_api = ToopherApi(self.key, self.secret)
            resource_type = validated_data['resource_type']
            if resource_type == 'authentication_request':
                return AuthenticationRequest(self._create_authentication_request_dict(validated_data), toopher_api)
            elif resource_type == 'pairing':
                return Pairing(self._create_pairing_dict(validated_data), toopher_api)
            elif resource_type == 'requester_user':
                return User(self._create_user_dict(validated_data), toopher_api)
            else:
                raise ToopherApiError('The postback resource type is not valid: {0}'.format(resource_type))

    def is_authentication_granted(self, data, request_token=None, **kwargs):
        try:
            authentication_request = self.process_postback(data, request_token)
            if isinstance(authentication_request, AuthenticationRequest):
                return True if authentication_request.granted and not authentication_request.pending else False
            else:
                logging.warning('The postback did not return an AuthenticationRequest')
                return False
        except Exception as e:
            logging.error(e)
            return False

    def _urldecode_iframe_data(self, data):
        data_dict = urlparse.parse_qs(data['toopher_iframe_data'])
        return dict((k,v[0]) for (k,v) in data_dict.items())

    def _validate_data(self, data, request_token, kwargs):

        self._check_for_missing_keys(data)
        self._verify_session_token(data.get('session_token'), request_token)
        self._check_if_signature_is_expired(data.get('timestamp'), kwargs)
        self._validate_signature(data)
        return data

    def _check_for_missing_keys(self, data):
        missing_keys = []
        for required_key in ('toopher_sig', 'timestamp', 'session_token'):
            if not required_key in data:
                missing_keys.append(required_key)

        if missing_keys:
            raise SignatureValidationError('Missing required keys: {0}'.format(', '.join(missing_keys)))

    def _verify_session_token(self, session_token, request_token):
        if request_token:
            if request_token != session_token:
                raise SignatureValidationError('Session token does not match expected value!')

    def _check_if_signature_is_expired(self, timestamp, kwargs):
        ttl = kwargs.pop('ttl') if 'ttl' in kwargs else DEFAULT_IFRAME_TTL
        ttl_valid = int(time.time()) - int(timestamp) < ttl
        if not ttl_valid:
            raise SignatureValidationError('TTL expired')

    def _validate_signature(self, data):
        maybe_sig = data['toopher_sig']
        del data['toopher_sig']

        try:
            computed_signature = self._calculate_signature(data)
        except Exception as e:
            raise SignatureValidationError('Error while calculating signature: {0}'.format(e.args[0]))

        if not maybe_sig == computed_signature:
            raise SignatureValidationError('Computed signature does not match submitted signature: {0} vs {1}'.format(computed_signature, maybe_sig))

    def _create_authentication_request_dict(self, data):
        return {
            'id': data['id'],
            'pending': True if data['pending'] == 'true' else False,
            'granted': True if data['granted'] == 'true' else False,
            'automated': True if data['automated'] == 'true' else False,
            'reason': data['reason'],
            'reason_code': data['reason_code'],
            'terminal': {
                'id': data['terminal_id'],
                'name': data['terminal_name'],
                'requester_specified_id': data['terminal_requester_specified_id'],
                'user': {
                    'id': data['pairing_user_id'],
                    'name': data['user_name'],
                    'toopher_authentication_enabled': True if data['user_toopher_authentication_enabled'] == 'true' else False
                }
            },
            'user': {
                'id': data['pairing_user_id'],
                'name': data['user_name'],
                'toopher_authentication_enabled': True if data['user_toopher_authentication_enabled'] == 'true' else False
            },
            'action': {
                'id': data['action_id'],
                'name': data['action_name']
            }
        }

    def _create_pairing_dict(self, data):
        return {
            'id': data['id'],
            'enabled': True if data['enabled'] == 'true' else False,
            'pending': True if data['pending'] == 'false' else False,
            'user': {
                'id': data['pairing_user_id'],
                'name': data['user_name'],
                'toopher_authentication_enabled': True if data['user_toopher_authentication_enabled'] == 'true' else False
            }
        }

    def _create_user_dict(self, data):
        return {
            'id': data['id'],
            'name': data['name'],
            'toopher_authentication_enabled': True if data['toopher_authentication_enabled'] == 'true' else False
        }

    def _calculate_signature(self, data):
        to_sign = urllib.urlencode(sorted(data.items())).encode('utf-8')
        secret = self.client.client_secret.encode('utf-8')
        return base64.b64encode(hmac.new(secret, to_sign, hashlib.sha1).digest())

    def _get_oauth_signed_url(self, uri, params, ttl):
        params['expires'] = str(int(time.time()) + ttl)
        return self.client.sign(uri + '?' + urllib.urlencode(params))[0]