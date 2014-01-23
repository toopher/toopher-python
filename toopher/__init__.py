import os
import requests_oauthlib
import sys

DEFAULT_BASE_URL = "https://api.toopher.com/v1"
VERSION = '1.1.0'

class ToopherApiError(Exception): pass
class UserDisabledError(ToopherApiError): pass
class UserUnknownError(ToopherApiError): pass
class TerminalUnknownError(ToopherApiError): pass
class PairingDeactivatedError(ToopherApiError): pass
error_codes_to_errors = {704: UserDisabledError,
                         705: UserUnknownError,
                         706: TerminalUnknownError}

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

        # TODO: Add an error code for PairingDeactivatedError.
        if ('pairing has been deactivated' in error_message.lower()
            or 'pairing has not been authorized' in error_message.lower()):
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
