import os
import sys

import toopher
from toopher import ToopherApiError

DEFAULT_USERNAME = 'demo@toopher.com'
DEFAULT_TERMINAL_NAME = 'my computer'

def print_sep(char='-'):
    print char*72


if __name__ == '__main__':
    print_sep('=')
    print 'Library Usage Demo'
    print_sep('=')
    print
    
    key = os.environ.get('TOOPHER_CONSUMER_KEY')
    secret = os.environ.get('TOOPHER_CONSUMER_SECRET')
    
    if not (key or secret):
        print 'Setup Credentials (set environment variables to prevent prompting)'
        print_sep()
        print 'Enter your requester credential details (from https://dev.toopher.com)'
        while not key:
            key = raw_input('TOOPHER_CONSUMER_KEY=')
        while not secret:
            secret = raw_input('TOOPHER_CONSUMER_SECRET=')

    if os.environ.get('TOOPHER_BASE_URL'):
        toopher.BASE_URL = os.environ.get('TOOPHER_BASE_URL').rstrip('/')
            
    api = toopher.ToopherApi(key, secret)
    
    while True:
        print 'Step 1: Pair requester with phone'
        print_sep('-')
        print 'Pairing phrases are generated on the mobile app'
        pairing_phrase = raw_input('Enter pairing phrase: ')
        while not pairing_phrase:
            print 'Please enter a pairing phrase to continue'
            pairing_phrase = raw_input('Enter pairing phrase: ')
            
        user_name = raw_input('Enter a username for this pairing [%s]: ' % DEFAULT_USERNAME)
        if not user_name:
            user_name = DEFAULT_USERNAME
            
        location_resolution = raw_input('Enter required location resolution [0..100]: ')

        print 'Sending pairing request...'
        
        try:
            pairing_status = api.pair(pairing_phrase, user_name, location_resolution)
            pairing_id = pairing_status.id
            break
        except ToopherApiError, e:
            print 'The pairing phrase was not accepted (reason: %s)' % e
            
    while True:
        raw_input('Authorize pairing on phone and then press return to continue.')
        print 'Checking status of pairing request...'
        
        try:
            pairing_status = api.get_pairing_status(pairing_id)
            if pairing_status.enabled:
                print 'Pairing complete'
                print
                break
            else:
                print 'The pairing has not been authorized by the phone yet'
        except ToopherApiError, e:
            raise
            print 'Could not check pairing status (reason: %s)' % e
            
    while True:
        print 'Step 2: Authenticate log in'
        print_sep()
        
        terminal_name = raw_input('Enter a terminal name for this authentication request [%s]: ' % DEFAULT_TERMINAL_NAME)
        if not terminal_name:
            terminal_name = DEFAULT_TERMINAL_NAME
            
        print 'Sending authentication request...'
        
        try:
            request_status = api.authenticate(pairing_id, terminal_name)
            request_id = request_status.id
        except ToopherApiError, e:
            print 'Error initiating authentication (reason: %s)' % e
            continue
        
        while True:
            raw_input('Response to authentication request on phone (if prompted) and then press return to continue.')
            print 'Checking status of authentication request...'
            
            try:
                request_status = api.get_authentication_status(request_id)
            except ToopherApiError, e:
                print 'Could not check authentication status (reason: %s)' % e
                continue
            
            if request_status.pending:
                print 'The authentication request has not received a response from the phone yet.'
            else:
                automation = 'automatically ' if request_status.automated else ''
                result = 'granted' if request_status.granted else 'denied'
                print 'The request was ' + automation + result + "!"
                if hasattr(request_status, 'reported_authenticator_location'):
                    print 'The Authenticator submitted the following location information!:'
                    for key in request_status.reported_authenticator_location:
                        print '\t{0} : {1}'.format(key, request_status.reported_authenticator_location[key])
                break
            
        raw_input('Press return to authenticate again, or Ctrl-C to exit')
