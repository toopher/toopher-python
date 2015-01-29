import os
import sys
import uuid

import toopher
from toopher import ToopherApiError

DEFAULT_USERNAME = 'demo@toopher.com'
DEFAULT_TERMINAL_NAME = 'my computer'

def print_horizontal_line(char='-'):
    print char*72

def print_text_with_underline(text, char='-'):
    print text
    print_horizontal_line(char)

def initialize_api():
    key = os.environ.get('TOOPHER_CONSUMER_KEY')
    secret = os.environ.get('TOOPHER_CONSUMER_SECRET')
    
    if not (key or secret):
        print_text_with_underline('Setup Credentials (set environment variables to prevent prompting)')
        print 'Enter your requester credential details (from https://dev.toopher.com)'
        while not key:
            key = raw_input('TOOPHER_CONSUMER_KEY=')
        while not secret:
            secret = raw_input('TOOPHER_CONSUMER_SECRET=')
            
    return toopher.ToopherApi(key, secret, os.environ.get('TOOPHER_BASE_URL'))

def pair_device_with_toopher(api):
    while True:
        print_text_with_underline('Step 1: Pair requester with phone')
        print 'Pairing phrases are generated on the mobile app'
        pairing_phrase = raw_input('Enter pairing phrase: ')
        while not pairing_phrase:
            print 'Please enter a pairing phrase to continue'
            pairing_phrase = raw_input('Enter pairing phrase: ')
            
        user_name = raw_input('Enter a username for this pairing [%s]: ' % DEFAULT_USERNAME)
        if not user_name:
            user_name = DEFAULT_USERNAME
            
        print 'Sending pairing request...'
        
        try:
            pairing = api.pair(user_name, pairing_phrase)
            break
        except ToopherApiError, e:
            print 'The pairing phrase was not accepted (reason: %s)' % e
            
    while True:
        raw_input('Authorize pairing on phone and then press return to continue.')
        print 'Checking status of pairing request...'
        
        try:
            pairing.refresh_from_server()
            if pairing.pending:
                print 'The pairing has not been authorized by the phone yet'
            elif pairing.enabled:
                print 'Pairing complete'
                print
                break
            else:
                print 'The pairing has been denied'
                break
        except ToopherApiError, e:
            raise
            print 'Could not check pairing status (reason: %s)' % e

    return pairing

def authenticate_with_toopher(api, pairing):
    terminal_extras = {}
    while True:
        print_text_with_underline('Step 2: Authenticate log in')
        terminal_name = raw_input('Enter a terminal name for this authentication request [%s]: ' % DEFAULT_TERMINAL_NAME)
        if not terminal_name:
            terminal_name = DEFAULT_TERMINAL_NAME

        if terminal_name in terminal_extras:
            terminal_extra = terminal_extras[terminal_name]
        else:
            terminal_extra = terminal_extras[terminal_name] = uuid.uuid4()
            
        print 'Sending authentication request...'
        
        try:
            auth_request = api.authenticate(pairing.id, terminal_name, terminal_name_extra=terminal_extra)
            auth_request_id = auth_request.id
        except ToopherApiError, e:
            print 'Error initiating authentication (reason: %s)' % e
            continue
        
        while True:
            raw_input('Response to authentication request on phone (if prompted) and then press return to continue.')
            print 'Checking status of authentication request...'
            
            try:
                auth_request.refresh_from_server()
            except ToopherApiError, e:
                print 'Could not check authentication request status (reason: %s)' % e
                continue
            
            if auth_request.pending:
                print 'The authentication request has not received a response from the phone yet.'
            else:
                automation = 'automatically ' if auth_request.automated else ''
                result = 'granted' if auth_request.granted else 'denied'
                print 'The request was ' + automation + result + "!"
                break
            
        raw_input('Press return to authenticate again, or Ctrl-C to exit')
        print

def demo():
    api = initialize_api()
    pairing = pair_device_with_toopher(api)
    if pairing.enabled:
       authenticate_with_toopher(api, pairing)

if __name__ == '__main__':
    print_horizontal_line('=')
    print_text_with_underline('Toopher Library Demo', '=')
    demo()
