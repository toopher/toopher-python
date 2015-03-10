#ToopherPython [![Build Status](https://travis-ci.org/toopher/toopher-python.png?branch=master)](https://travis-ci.org/toopher/toopher-python)

ToopherPython is a Toopher API library that simplifies the task of interfacing with the Toopher API from Python code.  This project wrangles all the required OAuth and JSON functionality so you can focus on just using the API.

### Python Version
* 2.6
* 2.7

### Documentation
Make sure you visit [https://dev.toopher.com](https://dev.toopher.com) to get acquainted with the Toopher API fundamentals.  The documentation there will tell you the details about the operations this API wrapper library provides.

## ToopherApi Workflow

### Step 1: Pair
Before you can enhance your website's actions with Toopher, your customers will need to pair their mobile device's Toopher app with your website.  To do this, they generate a unique pairing phrase from within the app on their mobile device.  You will need to prompt them for a pairing phrase as part of the Toopher enrollment process.  Once you have a pairing phrase, just send it to the Toopher web service and we'll return a pairing ID that you can use whenever you want to authenticate an action for that user.

```python
import toopher

# Create an API Object Using Your Credentials
api = toopher.ToopherApi("<your consumer key>", "<your consumer secret>")

# Step 1 - Pair with their mobile device's Toopher app
pairing = api.pair("username@yourservice.com", "pairing phrase")
```

### Step 2: Authenticate
You have complete control over what actions you want to authenticate using Toopher (for example: logging in, changing account information, making a purchase, etc.).  Just send us the user's pairing ID and a name for the terminal they're using and we'll make sure they actually want it to happen.

```python
# Step 2 - Authenticate a log in
authentication_request = api.authenticate(pairing.id, "terminal name")

# Once they've responded you can then check the status
authentication_request.refresh_from_server()
if not authentication_request.pending and authentication_request.granted:
	# Success!
```

## ToopherIframe Workflow
### Step 1: Embed a request in an IFRAME
1. Generate an authentication URL by providing a username.
2. Display a webpage to your user that embeds this URL within an `<iframe>` element.

```python
import toopher

# Create an API Object Using Your Credentials
iframe_api = toopher.ToopherIframe("<your consumer key>", "<your consumer secret>")


auth_iframe_url = iframe_api.get_authentication_url(username);

# Add an <iframe> element to your HTML:
# <iframe id="toopher_iframe" src=auth_iframe_url />
```

### Step 2: Validate the postback data

The simplest way to validate the postback data is to call `is_authentication_granted` to check if the authentication request was granted.

```python
# Returns boolean indicating if user should be granted access
authentication_request_granted = iframe_api.is_authentication_granted(form_data)

if authentication_request_granted:
    # Success!
```

### Handling Errors
If any request runs into an error a `ToopherApiError` will be thrown with more details on what went wrong.

### Demo
Check out `demo.py` for an example program that walks you through the whole process!  Just download the contents of this repo, make sure you have the dependencies listed above installed, and then run it like-a-this:
```shell
$ python demo.py
```

## Contributing
### Dependencies
This library uses the [Requests](http://docs.python-requests.org/en/latest/) library and [OAuthLib](https://oauthlib.readthedocs.org/en/latest/index.html) to handle OAuth signing and make the web requests.

Toopher uses [pip](https://pypi.python.org/pypi/pip) to install Python packages. To ensure all dependencies are up-to-date run:
```shell
$ pip install -r requirements.txt
```

### Tests
To run tests using [nose](http://nose.readthedocs.org/en/latest/) enter:
```shell
$ nosetests test
```