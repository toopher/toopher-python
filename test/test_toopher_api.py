import toopher
import unittest
import uuid
import json
import pickle
from .testutils import HttpClientMock

class ToopherApiTests(unittest.TestCase):
    toopher.DEFAULT_BASE_URL = 'https://api.toopher.test/v1'

    def setUp(self):
        self.api = toopher.ToopherApi('key', 'secret', 'https://api.toopher.test/v1')
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
            toopher.ToopherApi()
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
            pairing.random_key
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
            auth_request.random_key
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
        self.api.authenticate(self.id, self.terminal_name, test_param='42')
        self.assertEqual(self.api.advanced.raw.client.last_called_method, 'POST')
        self.assertEqual(self.api.advanced.raw.client.last_called_data['pairing_id'], self.id)
        self.assertEqual(self.api.advanced.raw.client.last_called_data['terminal_name'], self.terminal_name)
        self.assertEqual(self.api.advanced.raw.client.last_called_data['test_param'], '42')

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

    def test_action_missing_id_raises_error(self):
        data = self.action
        del data['id']
        def fn():
            toopher.Action(data)
        self.assertRaises(toopher.ToopherApiError, fn)

    def test_action_update_missing_name_raises_error(self):
        action = toopher.Action(self.action)
        def fn():
            action._update({'id':'1'})
        self.assertRaises(toopher.ToopherApiError, fn)

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
            self.api.authenticate('disabled user', 'terminal name')
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
            self.api.authenticate('unknown user', 'terminal name')
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
            self.api.authenticate(self.user_name, 'unknown terminal name')
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
            self.api.authenticate(self.user_name, requester_specified_id=self.requester_specified_id)
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
            self.api.authenticate(self.user_name, requester_specified_id=self.requester_specified_id)
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
        pickled_pairing = pickle.loads(pickle.dumps(pairing))

        self.assertEqual(pairing.id, pickled_pairing.id)
        self.assertEqual(pairing.user.id, pickled_pairing.user.id)
        self.assertEqual(pairing.user.name, pickled_pairing.user.name)
        self.assertTrue(pickled_pairing.enabled)
        self.assertTrue(pickled_pairing.pending)
        self.assertEqual(dir(pairing), dir(pickled_pairing))
