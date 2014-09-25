import os
from oauthlib import oauth1
import urllib
import hashlib
import hmac
import base64
import time
import requests_oauthlib
import sys

DEFAULT_BASE_URL = "https://api.toopher.com/v1"
DEFAULT_IFRAME_TTL = 100
IFRAME_VERSION = '2'
VERSION = '1.1.0'

class ToopherApiError(Exception): pass
class UserDisabledError(ToopherApiError): pass
class UserUnknownError(ToopherApiError): pass
class TerminalUnknownError(ToopherApiError): pass
class PairingDeactivatedError(ToopherApiError): pass

ERROR_CODE_USER_DISABLED = 704
ERROR_CODE_USER_UNKNOWN = 705
ERROR_CODE_TERMINAL_UNKNOWN = 706
ERROR_CODE_PAIRING_DEACTIVATED = 707

error_codes_to_errors = {ERROR_CODE_USER_DISABLED: UserDisabledError,
                         ERROR_CODE_USER_UNKNOWN: UserUnknownError,
                         ERROR_CODE_TERMINAL_UNKNOWN: TerminalUnknownError,
                         ERROR_CODE_PAIRING_DEACTIVATED: PairingDeactivatedError}

class SignatureValidationError(Exception): pass

class ToopherIframe(object):

    def __init__(self, key, secret, api_uri=None):
        self.secret = secret
        self.client = oauth1.Client(key, client_secret=secret, signature_type=oauth1.SIGNATURE_TYPE_QUERY)
        api_uri = api_uri if api_uri else DEFAULT_BASE_URL
        self.base_uri = api_uri.rstrip('/')

    def pair_uri(self, username, reset_email, ttl = DEFAULT_IFRAME_TTL):
        params = {
                'v':IFRAME_VERSION,
                'username':username,
                'reset_email':reset_email
                }
        return self.get_oauth_uri(self.base_uri + '/web/pair', params, ttl)

    def manage_user_uri(self, username, reset_email, ttl=DEFAULT_IFRAME_TTL):
        params = {
                'v':IFRAME_VERSION,
                'username':username,
                'reset_email':reset_email
                }
        return self.get_oauth_uri(self.base_uri + '/web/manage_user', params, ttl)

    def auth_uri(self, username, reset_email, action_name, automation_allowed, challenge_required, request_token, requester_metadata, ttl=DEFAULT_IFRAME_TTL, allow_inline_pairing=True):
        params = {
                'v':IFRAME_VERSION,
                'username':username,
                'reset_email':reset_email,
                'action_name':action_name,
                'automation_allowed':automation_allowed,
                'challenge_required':challenge_required,
                'session_token':request_token,
                'requester_metadata':requester_metadata,
                'allow_inline_pairing':allow_inline_pairing
                }
        return self.get_oauth_uri(self.base_uri + '/web/authenticate', params, ttl)

    def login_uri(self, username, reset_email, request_token, **kwargs):
        return self.auth_uri(username, reset_email, 'Log In', True, False, request_token, 'None', DEFAULT_IFRAME_TTL, **kwargs)

    def validate(self, data, request_token=None, ttl=DEFAULT_IFRAME_TTL):
        # make a mutable copy of the data
        data = dict(data)

        # flatten data if necessary
        if hasattr(data.values()[0], '__iter__'):
            data = dict((k,v[0]) for (k,v) in data.items())

        missing_keys = []
        for required_key in ('toopher_sig', 'timestamp', 'session_token'):
            if not required_key in data:
                missing_keys.append(required_key)

        if missing_keys:
            raise SignatureValidationError("Missing required keys: {0}".format(missing_keys))

        if request_token:
            if request_token != data.get('session_token'):
                raise SignatureValidationError("Session token does not match expected value!")

        maybe_sig = data['toopher_sig']
        del data['toopher_sig']
        signature_valid = False
        try:
            computed_signature  =self.signature(data)
            signature_valid = maybe_sig == computed_signature
        except Exception, e:
            raise SignatureValidationError("Error while calculating signature", e)

        if not signature_valid:
            raise SignatureValidationError("Computed signature does not match submitted signature: {0} vs {1}".format(computed_signature, maybe_sig))

        ttl_valid = int(time.time()) - int(data['timestamp']) < ttl
        if not ttl_valid:
            raise SignatureValidationError("TTL expired")

        return data

    def signature(self, data):
        to_sign = urllib.urlencode(sorted(data.items())).encode('utf-8')
        secret = self.client.client_secret.encode('utf-8')
        return base64.b64encode(hmac.new(secret, to_sign, hashlib.sha1).digest())

    def get_oauth_uri(self, uri, params, ttl):
        params['expires'] = str(int(time.time()) + ttl)
        return self.client.sign(uri + '?' + urllib.urlencode(params))[0]


class ToopherApi(object):
    def __init__(self, key, secret, api_url=None):
        self.client = requests_oauthlib.OAuth1Session(key, client_secret=secret)
        self.client.verify = True

        base_url = api_url if api_url else DEFAULT_BASE_URL
        self.base_url = base_url.rstrip('/')

    def pair(self, pairing_phrase, user_name, **kwargs):
        uri = self.base_url + "/pairings/create"
        params = {'pairing_phrase': pairing_phrase,
                  'user_name': user_name}

        params.update(kwargs)

        result = self._request(uri, "POST", params)
        return PairingStatus(result)

    def pair_qr(self, user_name, **kwargs):
        uri = self.base_url + '/pairings/create/qr'
        params = {'user_name': user_name}
        params.update(kwargs)
        result = self._request(uri, 'POST', params)
        return PairingStatus(result)

    def pair_sms(self, phone_number, user_name, phone_country=None):
        uri = self.base_url + "/pairings/create/sms"
        params = {'phone_number': phone_number,
                  'user_name': user_name}

        if phone_country:
            params['phone_country'] = phone_country

        result = self._request(uri, "POST", params)
        return PairingStatus(result)

    def get_pairing_status(self, pairing_id):
        uri = self.base_url + "/pairings/" + pairing_id

        result = self._request(uri, "GET")
        return PairingStatus(result)

    def authenticate(self, pairing_id, terminal_name, action_name=None, **kwargs):
        uri = self.base_url + "/authentication_requests/initiate"
        params = {'pairing_id': pairing_id,
                  'terminal_name': terminal_name}
        if action_name:
            params['action_name'] = action_name

        params.update(kwargs)

        result = self._request(uri, "POST", params)
        return AuthenticationStatus(result)

    def get_authentication_status(self, authentication_request_id):
        uri = self.base_url + "/authentication_requests/" + authentication_request_id

        result = self._request(uri, "GET")
        return AuthenticationStatus(result)

    def authenticate_with_otp(self, authentication_request_id, otp):
        uri = self.base_url + "/authentication_requests/" + authentication_request_id + '/otp_auth'
        params = {'otp' : otp}
        result = self._request(uri, "POST", params)
        return AuthenticationStatus(result)

    def authenticate_by_user_name(self, user_name, terminal_name_extra, action_name=None, **kwargs):
        kwargs.update(user_name=user_name, terminal_name_extra=terminal_name_extra)
        return self.authenticate('', '', action_name, **kwargs)

    def create_user_terminal(self, user_name, terminal_name, requester_terminal_id):
        uri = self.base_url + '/user_terminals/create'
        params = {'user_name': user_name,
                  'name': terminal_name,
                  'name_extra': requester_terminal_id}
        self._request(uri, 'POST', params)

    def set_toopher_enabled_for_user(self, user_name, enabled):
        uri = self.base_url + '/users'
        params = {'name': user_name}
        users = self._request(uri, 'GET', params)

        if len(users) > 1:
            raise ToopherApiError('Multiple users with name = %s' % user_name)
        elif not len(users):
            raise ToopherApiError('No users with name = %s' % user_name)

        uri = self.base_url + '/users/' + users[0]['id']
        params = {'disable_toopher_auth': not enabled}
        self._request(uri, 'POST', params)

    def _request(self, uri, method, params=None):
        data = {'params' if method == 'GET' else 'data': params}
        header_data = {'User-Agent':'Toopher-Python/%s (Python %s)' % (VERSION, sys.version.split()[0])}

        response = self.client.request(method, uri, headers=header_data, **data)
        try:
            content = response.json()
        except ValueError:
            raise ToopherApiError('Response from server could not be decoded as JSON.')

        if response.status_code >= 400:
            self._parse_request_error(content)

        return content

    def _parse_request_error(self, content):
        error_code = content['error_code']
        error_message = content['error_message']
        if error_code in error_codes_to_errors:
            error = error_codes_to_errors[error_code]
            raise error(error_message)

        if 'pairing has not been authorized' in error_message.lower():
            raise PairingDeactivatedError(error_message)

        raise ToopherApiError(error_message)

class PairingStatus(object):
    def __init__(self, json_response):
        try:
            self.id = json_response['id']
            self.enabled = json_response['enabled']

            user = json_response['user']
            self.user_id = user['id']
            self.user_name = user['name']
        except Exception as e:
            raise ToopherApiError("Could not parse pairing status from response" + e.message)

        self._raw_data = json_response

    def __nonzero__(self):
        return self.enabled

    def __getattr__(self, name):
        if name.startswith('__') or name not in self._raw_data:  # Exclude 'magic' methods to allow for (un)pickling
            return super(PairingStatus, self).__getattr__(name)
        else:
            return self._raw_data[name]


class AuthenticationStatus(object):
    def __init__(self, json_response):
        try:
            self.id = json_response['id']
            self.pending = json_response['pending']
            self.granted = json_response['granted']
            self.automated = json_response['automated']
            self.reason = json_response['reason']

            terminal = json_response['terminal']
            self.terminal_id = terminal['id']
            self.terminal_name = terminal['name']
        except Exception:
            raise ToopherApiError("Could not parse authentication status from response")

        self._raw_data = json_response

    def __nonzero__(self):
        return self.granted

    def __getattr__(self, name):
        if name.startswith('__') or name not in self._raw_data:  # Exclude 'magic' methods to allow for (un)pickling
            return super(AuthenticationStatus, self).__getattr__(name)
        else:
            return self._raw_data[name]


class ToopherApiError(Exception): pass
