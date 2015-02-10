import uuid
import requests_oauthlib
import sys
import binascii
import csv
import json

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
        self.oath_otp_validators = OathOtpValidators(api)


class ApiRawRequester(object):
    def __init__(self, key, secret, api_url):
        self.client = requests_oauthlib.OAuth1Session(key, client_secret=secret)
        self.client.verify = True

        base_url = api_url or DEFAULT_BASE_URL
        self.base_url = base_url.rstrip('/')

    def get(self, endpoint, **kwargs):
        url = self.base_url + endpoint
        return self._request(url, 'GET', kwargs)

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
        url = self.api.advanced.raw.base_url + '/qr/pairings/' + self.id
        return self.api.advanced.raw._request(url, 'GET', raw_request=True)

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
        params = {'name': self.name}
        self.api.advanced.raw.post(url, **params)

    def associate_oath_otp_validator(self, oath_otp_validator):
        url = '/users/{0}/oath_otp_validators/associate'.format(self.id)
        params = {}
        if oath_otp_validator.id:
            # identifying a previously-provisioned validator by ID
            params['id'] = oath_otp_validator.id
        elif oath_otp_validator.requester_specified_id and not oath_otp_validator.secret:
            # identifying a previously-provisioned validator by requester_specified_id
            params['requester_specified_id'] = oath_otp_validator.requester_specified_id
        elif oath_otp_validator.secret:
            # create and return a new validator
            params.update(oath_otp_validator._creation_dict())

        result = self.api.advanced.raw.post(url, **params)
        return OathOtpValidator(result, self.api)

    def dissociate_oath_otp_validator(self, oath_otp_validator):
        url = '/users/{0}/oath_otp_validators/associate'.format(self.id)
        params = { 'id' : oath_otp_validator.id }

        result = self.api.advanced.raw.post(url, **params)
        return OathOtpValidator(result, self.api)

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


class OathOtpValidators(object):
    class ImportFormat(object):
        SAFENET = {
                'csv_dialect' : 'whitespace',
                'secret_format' : 'hex',
                'header_map' : {
                    'Serial' : 'requester_specified_id',
                    'Seed' : 'secret'
                    },
                'defaults' : {
                    'otp_type' : 'hotp',
                    'otp_digits' : 6,
                    'algorithm' : 'sha1'
                    }
                }

    def __init__(self, api):
        self.api = api

    def provision(self, secret, requester_specified_id=None, otp_type='totp', otp_digits=8, algorithm='sha1', totp_step_size=30, **kwargs):
        url = '/oath_otp_validators/provision'
        params = {
                'secret': secret,
                'requester_specified_id': requester_specified_id,
                'otp_type': otp_type,
                'otp_digits': otp_digits,
                'algorithm': algorithm,
                'totp_step_size': totp_step_size
                }
        params.update(kwargs)
        result = self.api.advanced.raw.post(url, **params)
        return OathOtpValidator(result, self.api)

    def bulk_provision_from_csv(self, file_or_filename, style):
        def decode_validator_secret(encoded_secret, encoding):
            if encoding == 'hex':
                return encoded_secret
            elif encoding == 'ascii':
                return binascii.hexlify(bytearray(encoded_secret, 'utf-8'))
            else:
                raise ValueError('Unsupport secret encoding {0}'.format(encoding))

        def read_csv(f):
            csv.register_dialect('whitespace', delimiter=' ', skipinitialspace=True)
            dialect = style['csv_dialect']
            f.seek(0)
            reader = csv.DictReader(f, dialect=dialect)
            validators = []
            for row in reader:
                validator = style['defaults'].copy()
                for csv_field_name, api_field_name in style['header_map'].iteritems():
                    validator[api_field_name] = row[csv_field_name]
                if 'secret_format' in style:
                    validator['secret'] = decode_validator_secret(validator['secret'], style['secret_format'])
                validators.append(validator)
            return validators

        if isinstance(file_or_filename, basestring):
            with open(file_or_filename) as f:
                validators = read_csv(f)
        else:
            validators = read_csv(file_or_filename)

        url = '/oath_otp_validators/bulk_provision'
        params = {
            'oath_otp_validators' : json.dumps(validators)
            }
        response = self.api.advanced.raw.post(url, **params)
        validators_json_list = response['oath_otp_validators']
        validators_list = [OathOtpValidator(json_validator, self.api) for json_validator in validators_json_list]
        return validators_list

    def get_by_id(self, validator_id):
        url = '/oath_otp_validators/{0}'.format(validator_id)
        return OathOtpValidator(self.api.advanced.raw.get(url), api)

    def get_by_requester_specified_id(self, validator_requester_specified_id):
        url = '/oath_otp_validators'
        params = { 'requester_specified_id' : validator_requester_specified_id }
        return OathOtpValidator(self.api.advanced.raw.get(url, **params), api)


class OathOtpValidator(ToopherBase):
    def __init__(self, json_response, api ):
        self.api = api
        self._update(json_response)

    def associate_with_user(self, user):
        url = '/users/{0}/oath_otp_validators/associate'.format(user.id)
        params = { 'id' : self.id }
        result = self.api.advanced.raw.post(url, **params)
        self._update(result)

    def dissociate_from_user(self, user):
        url = '/users/{0}/oath_otp_validators/dissociate'.format(user.id)
        params = { 'id' : self.id }
        result = self.api.advanced.raw.post(url, **params)

    def resynchronize(self, otp_sequence):
        url = '/oath_otp_validators/{0}/resync'.format(self.id)
        params = { 'otp_sequence' : ','.join(otp_sequence) }
        self.api.advanced.raw.post(url, **params)

    def deactivate(self):
        url = '/oath_otp_validators/{0}/deactivate'.format(self.id)
        self.api.advanced.raw.post(url)

    def _update(self, json_response):
        try:
            self.id = json_response['id']
            self.requester_specified_id = json_response['requester_specified_id']
            self.otp_type = json_response['otp_type']
            self.otp_digits = json_response['otp_digits']
            self.algorithm = json_response['algorithm']
            self.totp_step_size = json_response['totp_step_size']
            self.hotp_event_counter = json_response['hotp_event_counter']
        except Exception:
            import traceback
            print traceback.format_exc()
            raise ToopherApiError("Could not parse oath_otp_validator from response")

        self._raw_data = json_response

