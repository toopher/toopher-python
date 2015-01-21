#ToopherPython

[![Build Status](https://travis-ci.org/toopher/toopher-python.png?branch=master)](https://travis-ci.org/toopher/toopher-python)

#### Introduction
ToopherPython is a Toopher API library that simplifies the task of interfacing with the Toopher API from Python code.  This project wrangles all the required OAuth and JSON functionality so you can focus on just using the API.

#### Learn the Toopher API
Make sure you visit [https://dev.toopher.com](https://dev.toopher.com) to get acquainted with the Toopher API fundamentals.  The documentation there will tell you the details about the operations this API wrapper library provides.

#### OAuth Authentication
First off, to access the Toopher API you'll need to sign up for an account at the [Toopher developers portal](https://dev.toopher.com) and create a "requester". When that process is complete, your requester is issued OAuth 1.0a credentials in the form of a consumer key and secret. Your key is used to identify your requester when Toopher interacts with your customers, and the secret is used to sign each request so that we know it is generated by you.  This library properly formats each request with your credentials automatically.

#### The Toopher Two-Step
Interacting with the Toopher web service involves two steps: pairing, and authenticating.

##### Pair
Before you can enhance your website's actions with Toopher, your customers will need to pair their phone's Toopher app with your website.  To do this, they generate a unique, nonsensical "pairing phrase" from within the app on their phone.  You will need to prompt them for a pairing phrase as part of the Toopher enrollment process.  Once you have a pairing phrase, just send it to the Toopher web service and we'll return a pairing ID that you can use whenever you want to authenticate an action for that user.

##### Authenticate
You have complete control over what actions you want to authenticate using Toopher (for example: logging in, changing account information, making a purchase, etc.).  Just send us the user's pairing ID, a name for the terminal they're using, and a description of the action they're trying to perform and we'll make sure they actually want it to happen.

#### Librarified
This library makes it super simple to do the Toopher two-step.  Check it out:

```python
import toopher

# Create an API object using your credentials
api = toopher.ToopherApi("<your consumer key>", "<your consumer secret>")

# Step 1 - Pair with their phone's Toopher app
# With pairing phrase
pairing = api.pair("username@yourservice.com", "pairing phrase")
# With SMS (country_code optional)
pairing = api.pair("username@yourservice.com", "555-555-5555", country_code="1")
# With QR code
pairing = api.pair("username@yourservice.com")

# Step 2 - Authenticate a log in
# With pairing_id
auth = api.authenticate(pairing.id, "my computer")
# With username
auth = api.authenticate("username", "requester_terminal_id")

# Once they've responded you can then check the status
auth.refresh_from_server(api)
if (auth.pending == False and auth.granted == True):
	# Success!
```

#### Handling Errors
If any request runs into an error a `ToopherApiError` will be thrown with more details on what went wrong.

#### Zero-Storage usage option
Requesters can choose to integrate the Toopher API in a way does not require storing any per-user data such as Pairing ID and Terminal ID - all of the storage
is handled by the Toopher API Web Service, allowing your local database to remain unchanged.  If the Toopher API needs more data, it will `raise()` a specific
error that allows your code to respond appropriately.

```python
try:
    # optimistically try to authenticate against Toopher API with username and a Terminal Identifier
    # Terminal Identifer is typically a randomly generated secure browser cookie.  It does not
    # need to be human-readable
    auth = api.authenticate("username", "requester_terminal_id")

    # if you got here, everything is good!  poll the auth request as described above
    # there are four distinct errors ToopherAPI can return if it needs more data
except UserDisabledError:
    # you have marked this user as disabled in the Toopher API.
except UserUnknownError:
    # This user has not yet paired a mobile device with their account.  Pair them
    # using api.pair() as described above, then re-try authentication
except TerminalUnknownError:
    # This user has not assigned a "Friendly Name" to this terminal identifier.
    # Prompt them to enter a terminal name, then submit that "friendly name" to
    # the Toopher API:
    #   api.advanced.user_terminals.create("username", "terminal_name", "requester_terminal_id")
    # Afterwards, re-try authentication
except PairingDeactivatedError:
    # this user does not have an active pairing,
    # typically because they deleted the pairing.  You can prompt
    # the user to re-pair with a new mobile device.
```

#### Dependencies
This library uses the [Requests](http://docs.python-requests.org/en/latest/) library to handle OAuth signing and to make the web requests.  If you install using pip (or easy_install) they'll be installed automatically for you. 

#### Try it out
Check out `demo.py` for an example program that walks you through the whole process!  Just download the contents of this repo, make sure you have the dependencies listed above installed, and then run it like-a-this:
```shell
$ python ./demo.py
```
