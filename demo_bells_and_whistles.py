import os
import sys
import uuid

import toopher
from toopher import ToopherApiError
import argparse

DEFAULT_USERNAME = 'demo@toopher.com'
DEFAULT_TERMINAL_NAME = 'my computer'

def print_sep(char='-'):
    print char*72


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Toopher Library Usage Demo')
    parser.add_argument('--sms', dest='sms_authentication', action='store_true',
                    help='Use SMS Authentication mode (SMS messages instead of Smartphone push)')
    parser.add_argument('--sms-inband-reply', dest='sms_inband_reply', action='store_true',
                    help='Send a OTP to user over SMS for entry through the website (instead of prompting them to reply via SMS).  This option only makes sense if --sms is also supplied.')
    args = parser.parse_args()

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
            
    api = toopher.ToopherApi(key, secret, os.environ.get('TOOPHER_BASE_URL'))
    
    while True:
        print 'Step 1: Pair requester with phone'
        print_sep('-')
        if args.sms_authentication:
            pair_func = api.pair_sms
            pair_help = 'Non-US numbers should start with a "+" and include the country code.'
            pair_type = 'mobile number'
        else:
            pair_func = api.pair
            pair_help = 'Pairing phrases are generated on the mobile app'
            pair_type = 'pairing phrase'
        
        print pair_help
        pairing_key = raw_input('Enter %s: ' % pair_type)
        while not pairing_key:
            print 'Please enter a %s to continue' % pair_type
            pairing_key = raw_input('Enter %s: ' % pair_type)
            
        user_name = raw_input('Enter a username for this pairing [%s]: ' % DEFAULT_USERNAME)
        if not user_name:
            user_name = DEFAULT_USERNAME
            
        print 'Sending pairing request...'
        
        try:
            pairing_status = pair_func(pairing_key, user_name)
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
            
    terminal_extras = {}

    while True:
        print 'Step 2: Authenticate log in'
        print_sep()
        
        terminal_name = raw_input('Enter a terminal name for this authentication request [%s]: ' % DEFAULT_TERMINAL_NAME)
        if not terminal_name:
            terminal_name = DEFAULT_TERMINAL_NAME

        if terminal_name in terminal_extras:
            terminal_extra = terminal_extras[terminal_name]
        else:
            terminal_extra = terminal_extras[terminal_name] = uuid.uuid4()
            
        print 'Sending authentication request...'
        
        try:
            request_status = api.authenticate(pairing_id, terminal_name, terminal_name_extra=terminal_extra, use_sms_inband_reply=args.sms_inband_reply)
            request_id = request_status.id
        except ToopherApiError, e:
            print 'Error initiating authentication (reason: %s)' % e
            continue
        
        while True:
            if args.sms_inband_reply:
                otp = raw_input('Enter the One-Time-Password that was sent to your phone to continue: ')
            else:
                otp = None
                raw_input('Response to authentication request on phone (if prompted) and then press return to continue.')
            print 'Checking status of authentication request...'
            
            try:
                if otp:
                    request_status = api.authenticate_with_otp(request_id, otp)
                else:
                    request_status = api.get_authentication_request_by_id(request_id)
            except ToopherApiError, e:
                print 'Could not check authentication status (reason: %s)' % e
                continue
            
            if request_status.pending:
                print 'The authentication request has not received a response from the phone yet.'
            else:
                automation = 'automatically ' if request_status.automated else ''
                result = 'granted' if request_status.granted else 'denied'
                print 'The request was ' + automation + result + "!"
                break
            
        raw_input('Press return to authenticate again, or Ctrl-C to exit')
