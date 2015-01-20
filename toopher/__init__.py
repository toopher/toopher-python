import os
from oauthlib import oauth1
import urllib
import hashlib
import hmac
import base64
import uuid
import time
import requests_oauthlib
import sys

DEFAULT_BASE_URL = "https://api.toopher.com/v1"
DEFAULT_IFRAME_TTL = 100
IFRAME_VERSION = '2'
VERSION = '2.0.0'

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

    def get_user_management_iframe_url(self, username, reset_email, **kwargs):
        if not 'ttl' in kwargs:
            ttl = DEFAULT_IFRAME_TTL
        else:
            ttl = kwargs.pop('ttl')

        params = {
                'v':IFRAME_VERSION,
                'username':username,
                'reset_email':reset_email
                }
        return self._get_oauth_signed_url(self.base_uri + '/web/manage_user', params, ttl)

    # Params still TBD
    def get_auth_iframe_url(self, username, reset_email, request_token, action_name='Log In', requester_metadata='None', **kwargs):
        if not 'allow_inline_pairing' in kwargs:
            kwargs['allow_inline_pairing'] = True
        if not 'automation_allowed' in kwargs:
            kwargs['automation_allowed'] = True
        if not 'challenge_required' in kwargs:
            kwargs['challenge_required'] = False
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

    def validate_postback(self, data, request_token=None, **kwargs):
        if not 'ttl' in kwargs:
            ttl = DEFAULT_IFRAME_TTL
        else:
            ttl = kwargs.pop('ttl')

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
            computed_signature  =self._signature(data)
            signature_valid = maybe_sig == computed_signature
        except Exception, e:
            raise SignatureValidationError("Error while calculating signature", e)

        if not signature_valid:
            raise SignatureValidationError("Computed signature does not match submitted signature: {0} vs {1}".format(computed_signature, maybe_sig))

        ttl_valid = int(time.time()) - int(data['timestamp']) < ttl
        if not ttl_valid:
            raise SignatureValidationError("TTL expired")

        return data

    def _signature(self, data):
        to_sign = urllib.urlencode(sorted(data.items())).encode('utf-8')
        secret = self.client.client_secret.encode('utf-8')
        return base64.b64encode(hmac.new(secret, to_sign, hashlib.sha1).digest())

    def _get_oauth_signed_url(self, uri, params, ttl):
        params['expires'] = str(int(time.time()) + ttl)
        return self.client.sign(uri + '?' + urllib.urlencode(params))[0]


class ToopherApi(object):
    def __init__(self, key, secret, api_url=None):
        self.client = requests_oauthlib.OAuth1Session(key, client_secret=secret)
        self.client.verify = True

        base_url = api_url if api_url else DEFAULT_BASE_URL
        self.base_url = base_url.rstrip('/')

    def pair(self, username, phrase_or_num=None, **kwargs):
        params = {'user_name': username}
        params.update(kwargs)
        if phrase_or_num:
            if any(c.isdigit() for c in phrase_or_num):
                url = '/pairings/create/sms'
                params.update(phone_number=phrase_or_num)
            else:
                url = '/pairings/create'
                params.update(pairing_phrase=phrase_or_num)
        else:
            url = '/pairings/create/qr'

        result = self.post(url, **params)
        return Pairing(result)

    def get_pairing_by_id(self, pairing_id):
        url = '/pairings/' + pairing_id
        result = self.get(url)
        return Pairing(result)

    def authenticate(self, id_or_username, terminal, action_name=None, **kwargs):
        url = '/authentication_requests/initiate'
        try:
            uuid.UUID(id_or_username)
            params = {'pairing_id': id_or_username,
                      'terminal_name': terminal}
        except:
            params = {'user_name': id_or_username,
                      'terminal_name_extra': terminal}
        if action_name:
            params['action_name'] = action_name
        params.update(kwargs)

        result = self.post(url, **params)
        return AuthenticationRequest(result)

    def get_authentication_request_by_id(self, authentication_request_id):
        url = '/authentication_requests/' + authentication_request_id
        result = self.get(url)
        return AuthenticationRequest(result)

    def create_user(self, username, **kwargs):
        url = '/users/create'
        params = {'name': username}
        params.update(kwargs)
        result = self.post(url, **params)
        return User(result)

    def reset_user(self, username):
        url = '/users/reset'
        params = {'name': username}
        self.post(url, **params)
        return True # would raise error in _request if failed

    def get_user_by_id(self, user_id):
        url = '/users/' + user_id
        result = self.get(url)
        return User(result)

    def create_user_terminal(self, username, terminal_name, requester_terminal_id, **kwargs):
        url = '/user_terminals/create'
        params = {'user_name': username,
                  'name': terminal_name,
                  'name_extra': requester_terminal_id}
        params.update(kwargs)
        result = self.post(url, **params)
        return UserTerminal(result)

    def get_user_terminal_by_id(self, terminal_id):
        url = '/user_terminals/' + terminal_id
        result = self.get(url)
        return UserTerminal(result)

    def _set_toopher_disabled_for_user(self, username, disable):
        url = '/users'
        users = self.get(url, user_name=username)

        if len(users) > 1:
            raise ToopherApiError('Multiple users with name = %s' % username)
        elif not len(users):
            raise ToopherApiError('No users with name = %s' % username)

        url = '/users/' + users[0]['id']
        self.post(url, disable_toopher_auth=disable)

    def enable_user(self, username):
        self._set_toopher_disabled_for_user(username, False)

    def disable_user(self, username):
        self._set_toopher_disabled_for_user(username, True)

    def get_pairing_reset_link(self, pairing_id, **kwargs):
        if not 'security_question' in kwargs:
            kwargs['security_question'] = None
        if not 'security_answer' in kwargs:
            kwargs['security_answer'] = None

        url = '/pairings/' + pairing_id + '/generate_reset_link'
        result = self.post(url, **kwargs)
        return result['url']

    def email_pairing_reset_link_to_user(self, pairing_id, email, **kwargs):
        params = {'reset_email': email}
        params.update(kwargs)
        url = '/pairings/' + pairing_id + '/send_reset_link'
        self.post(url, **params)
        return True #would raise error in _request if failed

    def get(self, endpoint, **kwargs):
        url = self.base_url + endpoint
        return self._request(url, 'GET', kwargs)

    def post(self, endpoint, **kwargs):
        url = self.base_url + endpoint
        return self._request(url, 'POST', kwargs)

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

    def _request_raw(self, uri, method, params=None):
        data = {'params' if method == 'GET' else 'data': params}
        header_data = {'User-Agent':'Toopher-Python/%s (Python %s)' % (VERSION, sys.version.split()[0])}

        response = self.client.request(method, uri, headers=header_data, **data)

        if response.status_code >= 400:
            self._parse_request_error(content)

        return response.content

    def _parse_request_error(self, content):
        error_code = content['error_code']
        error_message = content['error_message']
        if error_code in error_codes_to_errors:
            error = error_codes_to_errors[error_code]
            raise error(error_message)

        if 'pairing has not been authorized' in error_message.lower():
            raise PairingDeactivatedError(error_message)

        raise ToopherApiError(error_message)


class Pairing(object):
    def __init__(self, json_response):
        try:
            self.id = json_response['id']
            self.enabled = json_response['enabled']
            self.pending = json_response['pending']
            self.user = User(json_response['user'])
        except Exception as e:
            raise ToopherApiError("Could not parse pairing status from response" + e.message)

        self._raw_data = json_response

    def __nonzero__(self):
        return self.enabled

    def __getattr__(self, name):
        if name.startswith('__') or name not in self._raw_data:  # Exclude 'magic' methods to allow for (un)pickling
            return super(Pairing, self).__getattr__(name)
        else:
            return self._raw_data[name]

    def refresh_from_server(self, api):
        url = '/pairings/' + self.id
        result = api.get(url)
        self.enabled = result['enabled']
        self.pending = result['pending']
        self.user.update(result['user'])
        self._raw_data = result

    def get_qr_code_image(self, api):
        url = api.base_url + '/qr/pairings/' + self.id
        return api._request_raw(url, 'GET')


class AuthenticationRequest(object):
    def __init__(self, json_response):
        try:
            self.terminal = UserTerminal(json_response['terminal'])
        except Exception:
            raise ToopherApiError("Could not parse authentication from response")
        self.update(json_response)

    def __nonzero__(self):
        return self.granted

    def __getattr__(self, name):
        if name.startswith('__') or name not in self._raw_data:  # Exclude 'magic' methods to allow for (un)pickling
            return super(AuthenticationRequest, self).__getattr__(name)
        else:
            return self._raw_data[name]

    def authenticate_with_otp(self, otp, api, **kwargs):
        url = '/authentication_requests/' + self.id + '/otp_auth'
        params = {'otp' : otp}
        params.update(kwargs)
        result = api.post(url, **params)
        self.update(result)

    def refresh_from_server(self, api):
        url = '/authentication_requests/' + self.id
        result = api.get(url)
        self.update(result)

    def update(self, json_response):
        try:
            self.id = json_response['id']
            self.pending = json_response['pending']
            self.granted = json_response['granted']
            self.automated = json_response['automated']
            self.reason = json_response['reason']
            self.terminal.update(json_response['terminal'])
        except Exception:
            raise ToopherApiError("Could not parse authentication status from response")

        self._raw_data = json_response


class UserTerminal(object):
    def __init__(self, json_response):
        self.update(json_response)

    def __getattr__(self, name):
        if name.startswith('__') or name not in self._raw_data:  # Exclude 'magic' methods to allow for (un)pickling
            return super(UserTerminal, self).__getattr__(name)
        else:
            return self._raw_data[name]

    def refresh_from_server(self, api):
        url = '/user_terminals/' + self.id
        result = api.get(url)

        self.name = result["name"]
        self.name_extra = result["name_extra"]
        user = result["user"]
        self.user_name = user["name"]
        self._raw_data = result

    def update(self, json_response):
        try:
            self.id = json_response['id']
            self.name = json_response['name']
            self.name_extra = json_response['name_extra']
            user = json_response['user']
            self.user_id = user['id']
            self.user_name = user['name']
        except Exception:
            raise ToopherApiError("Could not parse user terminal from response")

        self._raw_data = json_response


class User(object):
    def __init__(self, json_response):
        self.update(json_response)

    def __getattr__(self, name):
        if name.startswith('__') or name not in self._raw_data:  # Exclude 'magic' methods to allow for (un)pickling
            return super(User, self).__getattr__(name)
        else:
            return self._raw_data[name]

    def refresh_from_server(self, api):
        url = '/users/' + self.id
        result = api.get(url)
        self.update(result)

    def enable(self, api):
        url = '/users/' + self.id
        result = api.post(url, disable_toopher_auth=False)
        self.update(result)

    def disable(self, api):
        url = '/users/' + self.id
        result = api.post(url, disable_toopher_auth=True)
        self.update(result)

    def reset(self, api):
        return api.reset_user(self.name)

    def update(self, json_response):
        try:
            self.id = json_response['id']
            self.name = json_response['name']
            self.disable_toopher_auth = json_response['disable_toopher_auth']
        except Exception:
            raise ToopherApiError("Could not parse user from response")

        self._raw_data = json_response


class ToopherApiError(Exception): pass
