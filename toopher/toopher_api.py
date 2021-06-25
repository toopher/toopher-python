import uuid
import requests_oauthlib
import sys

DEFAULT_BASE_URL = 'https://api.toopher.com/v1'
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

class ToopherApi(object):
    def __init__(self, key, secret, api_url=None):
        self.advanced = AdvancedApiUsageFactory(key, secret, api_url, self)

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

        result = self.advanced.raw.post(url, **params)
        return Pairing(result, self)

    def authenticate(self, id_or_username, terminal_name=None, requester_specified_id=None, action_name=None, **kwargs):
        url = '/authentication_requests/initiate'
        try:
            uuid.UUID(id_or_username)
            params = {'pairing_id': id_or_username}
        except:
            params = {'user_name': id_or_username}
        if terminal_name:
            params['terminal_name'] = terminal_name
        if requester_specified_id:
            params['requester_specified_terminal_id'] = requester_specified_id
        if action_name:
            params['action_name'] = action_name
        params.update(kwargs)

        result = self.advanced.raw.post(url, **params)
        return AuthenticationRequest(result, self)


class AdvancedApiUsageFactory(object):
    def __init__(self, key, secret, api_url, api):
        self.raw = ApiRawRequester(key, secret, api_url)
        self.pairings = Pairings(api)
        self.authentication_requests = AuthenticationRequests(api)
        self.users = Users(api)
        self.user_terminals = UserTerminals(api)


class ApiRawRequester(object):
    def __init__(self, key, secret, api_url):
        self.client = requests_oauthlib.OAuth1Session(key, client_secret=secret)
        self.client.verify = True

        base_url = api_url or DEFAULT_BASE_URL
        self.base_url = base_url.rstrip('/')

    def get(self, endpoint, **kwargs):
        url = self.base_url + endpoint
        return self._request(url, 'GET', kwargs)

    def get_raw(self, endpoint):
        url = self.base_url + endpoint
        return self._request(url, 'GET', raw_request=True)

    def post(self, endpoint, **kwargs):
        url = self.base_url + endpoint
        return self._request(url, 'POST', kwargs)

    def _request(self, uri, method, params=None, raw_request=False):
        data = {'params' if method == 'GET' else 'data': params}
        header_data = {'User-Agent':'Toopher-Python/%s (Python %s)' % (VERSION, sys.version.split()[0])}

        response = self.client.request(method, uri, headers=header_data, **data)
        try:
            content = response.json()
        except ValueError:
            raise ToopherApiError('Response from server could not be decoded as JSON.')

        if response.status_code >= 400:
            self._parse_request_error(content)

        if raw_request:
            return response.content
        else:
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


class ToopherObjectFactory(object):
    def __init__(self, api):
        self.api = api


class Pairings(ToopherObjectFactory):
    def get_by_id(self, pairing_id):
        url = '/pairings/' + pairing_id
        result = self.api.advanced.raw.get(url)
        return Pairing(result, self.api)


class AuthenticationRequests(ToopherObjectFactory):
    def get_by_id(self, authentication_request_id):
        url = '/authentication_requests/' + authentication_request_id
        result = self.api.advanced.raw.get(url)
        return AuthenticationRequest(result, self.api)


class UserTerminals(ToopherObjectFactory):
    def create(self, username, terminal_name, requester_specified_id, **kwargs):
        url = '/user_terminals/create'
        params = {'user_name': username,
                  'name': terminal_name,
                  'name_extra': requester_specified_id}
        params.update(kwargs)
        result = self.api.advanced.raw.post(url, **params)
        return UserTerminal(result, self.api)

    def get_by_id(self, terminal_id):
        url = '/user_terminals/' + terminal_id
        result = self.api.advanced.raw.get(url)
        return UserTerminal(result, self.api)


class Users(ToopherObjectFactory):
    def create(self, username, **kwargs):
        url = '/users/create'
        params = {'name': username}
        params.update(kwargs)
        result = self.api.advanced.raw.post(url, **params)
        return User(result, self.api)

    def get_by_id(self, user_id):
        url = '/users/' + user_id
        result = self.api.advanced.raw.get(url)
        return User(result, self.api)

    def get_by_name(self, username):
        url = '/users'
        users = self.api.advanced.raw.get(url, name=username)

        if len(users) > 1:
            raise ToopherApiError('Multiple users with name = %s' % username)
        elif not len(users):
            raise ToopherApiError('No users with name = %s' % username)

        return User(users[0], self.api)


class ToopherBase(object):
    def __getattr__(self, name):
        if name.startswith('__') or name not in self.raw_response:  # Exclude 'magic' methods to allow for (un)pickling
            return super(ToopherBase, self).__getattribute__(name)
        else:
            return self.raw_response[name]


class Pairing(ToopherBase):
    def __init__(self, json_response, api):
        self.api = api
        self.raw_response = json_response
        try:
            self.id = json_response['id']
            self.enabled = json_response['enabled']
            self.pending = json_response['pending']
            self.user = User(json_response['user'], api)
        except Exception as e:
            raise ToopherApiError('Could not parse pairing from response: %s' % e.args)

    def __nonzero__(self):
        return self.enabled

    def refresh_from_server(self):
        url = '/pairings/' + self.id
        result = self.api.advanced.raw.get(url)
        self._update(result)

    def get_qr_code_image(self):
        url = '/qr/pairings/' + self.id
        return self.api.advanced.raw.get_raw(url)

    def get_reset_link(self, **kwargs):
        if not 'security_question' in kwargs:
            kwargs['security_question'] = None
        if not 'security_answer' in kwargs:
            kwargs['security_answer'] = None

        url = '/pairings/' + self.id + '/generate_reset_link'
        result = self.api.advanced.raw.post(url, **kwargs)
        return result['url']

    def email_reset_link(self, email, **kwargs):
        params = {'reset_email': email}
        params.update(kwargs)
        url = '/pairings/' + self.id + '/send_reset_link'
        self.api.advanced.raw.post(url, **params)

    def _update(self, json_response):
        self.raw_response = json_response
        try:
            self.enabled = json_response['enabled']
            self.pending = json_response['pending']
            self.user._update(json_response['user'])
        except Exception as e:
            raise ToopherApiError('Could not parse pairing from response: %s' % e.args)


class AuthenticationRequest(ToopherBase):
    def __init__(self, json_response, api):
        self.api = api
        self.raw_response = json_response
        try:
            self.id = json_response['id']
            self.pending = json_response['pending']
            self.granted = json_response['granted']
            self.automated = json_response['automated']
            self.reason = json_response['reason']
            self.reason_code = json_response['reason_code']
            self.terminal = UserTerminal(json_response['terminal'], api)
            self.user = User(json_response['user'], api)
            self.action = Action(json_response['action'])
        except Exception as e:
            raise ToopherApiError('Could not parse authentication request from response: %s' % e.args)

    def __nonzero__(self):
        return self.granted


    def grant_with_otp(self, otp, **kwargs):
        url = '/authentication_requests/' + self.id + '/otp_auth'
        params = {'otp' : otp}
        params.update(kwargs)
        result = self.api.advanced.raw.post(url, **params)
        self._update(result)

    def refresh_from_server(self):
        url = '/authentication_requests/' + self.id
        result = self.api.advanced.raw.get(url)
        self._update(result)

    def _update(self, json_response):
        self.raw_response = json_response
        try:
            self.pending = json_response['pending']
            self.granted = json_response['granted']
            self.automated = json_response['automated']
            self.reason = json_response['reason']
            self.reason_code = json_response['reason_code']
            self.terminal._update(json_response['terminal'])
            self.user._update(json_response['user'])
            self.action._update(json_response['action'])
        except Exception as e:
            raise ToopherApiError('Could not parse authentication request from response: %s' % e.args)


class User(ToopherBase):
    def __init__(self, json_response, api):
        self.api = api
        self.raw_response = json_response
        try:
            self.id = json_response['id']
            self.name = json_response['name']
            self.toopher_authentication_enabled = json_response['toopher_authentication_enabled']
        except Exception as e:
            raise ToopherApiError('Could not parse user from response: %s' % e.args)

    def refresh_from_server(self):
        url = '/users/' + self.id
        result = self.api.advanced.raw.get(url)
        self._update(result)

    def enable_toopher_authentication(self):
        url = '/users/' + self.id
        result = self.api.advanced.raw.post(url, toopher_authentication_enabled=True)
        self._update(result)

    def disable_toopher_authentication(self):
        url = '/users/' + self.id
        result = self.api.advanced.raw.post(url, toopher_authentication_enabled=False)
        self._update(result)

    def reset(self):
        url = '/users/reset'
        params = {'user_name': self.name}
        self.api.advanced.raw.post(url, **params)

    def _update(self, json_response):
        self.raw_response = json_response
        try:
            self.name = json_response['name']
            self.toopher_authentication_enabled = json_response['toopher_authentication_enabled']
        except Exception as e:
            raise ToopherApiError('Could not parse user from response: %s' % e.args)


class UserTerminal(ToopherBase):
    def __init__(self, json_response, api):
        self.api = api
        self.raw_response = json_response
        try:
            self.id = json_response['id']
            self.name = json_response['name']
            self.requester_specified_id = json_response['requester_specified_id']
            self.user = User(json_response['user'], api)
        except Exception as e:
            raise ToopherApiError('Could not parse user terminal from response: %s' % e.args)

    def refresh_from_server(self):
        url = '/user_terminals/' + self.id
        result = self.api.advanced.raw.get(url)
        self._update(result)

    def _update(self, json_response):
        self.raw_response = json_response
        try:
            self.name = json_response['name']
            self.requester_specified_id = json_response['requester_specified_id']
            self.user._update(json_response['user'])
        except Exception as e:
            raise ToopherApiError('Could not parse user terminal from response: %s' % e.args)

class Action(ToopherBase):
    def __init__(self, json_response):
        self.raw_response = json_response
        try:
            self.id = json_response['id']
            self.name = json_response['name']
        except Exception as e:
            raise ToopherApiError('Could not parse action from response %s' % e.args)

    def _update(self, json_response):
        self.raw_response = json_response
        try:
            self.name = json_response['name']
        except Exception as e:
            raise ToopherApiError('Could not parse action from response: %s' % e.args)
