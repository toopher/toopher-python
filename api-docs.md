Toopher API
===

1. ToopherIframe
    * [get\_auth\_iframe\_url](#get\_auth\_iframe\_url)
    * [get\_user\_management\_iframe\_url](#get\_user\_management\_iframe\_url)
    * [validate\_postback](#validate\_postback)

2. ToopherApi
    * [pair](#pair)
    * [authenticate](#authenticate)

3. Advanced - ApiRawRequester
    * [get](#get)
    * [post](#post)

4. Advanced - Pairings
    * [get\_by\_id](#get\_by\_id)

5. Advanced - AuthenticationRequests
    * [get\_by\_id](#get\_by\_id)

6. Advanced - UserTerminals
    * [create](#create)
    * [get\_by\_id](#get\_by\_id)

7. Advanced - Users
    * [create](#create)
    * [get\_by\_id](#get\_by\_id)
    * [get\_by\_name](#get\_by\_name)

8. Pairing
    * [refresh\_from\_server](#refresh\_from\_server)
    * [get\_qr\_code\_image](#get\_qr\_code\_image)
    * [get\_reset\_link](#get\_reset\_link)
    * [email\_reset\_link\_to\_user](#email\_reset\_link\_to\_user)

9. AuthenticationRequest
    * [refresh\_from\_server](#refresh\_from\_server)
    * [authenticate\_with\_otp](#authenticate\_with\_otp)

10. UserTerminal
    * [refresh\_from\_server](#refresh\_from\_server)

11. User
    * [refresh\_from\_server](#refresh\_from\_server)
    * [enable](#enable)
    * [disable](#disable)
    * [reset](#reset)


# ToopherIframe

Toopher's IFrame-based authentication flow is the simplest way for web developers to integrate Toopher Two-Factor Authentication into an application. The IFrame-based authentication flow works by inserting an `<iframe>` element into the HTML displayed to the user after a successful username/password validation (but before they are actually logged-in to the service).

##### Arguments
| Name | | Format | Default |
| -----: | :----- | :----- | :---- |
| key | required | string ||
| secret | required | string ||
| api_uri | optional | string | 'https://api.toopher.com/v1'|

##### Example
```python
api = toopher.ToopherIframe('<your_consumer_key>', '<your_consumer_secret>')
```

### get\_auth\_iframe\_url

Retrieves an OAuth-signed pairing and authentication IFrame URL for a given user.

##### Arguments
| Name |  Required? | Format | Default |
| -----: | :----- | :----- | :--- |
| username | required | string | |
| reset_email | required | string | |
| request_token | required | string | |
| action_name | optional | string | 'Log In'|
| requester_metadata | optional | string | None|
| **kwargs | optional | dict | |

##### Example
```python
# Create an instance of ToopherIframe
api.get_authentication_url('username@yourservice.com', 'reset_email@yourservice.com', 'request_token')
```

### get\_user\_management\_iframe\_url

Retrieves an OAuth-signed pairing IFrame URL for a given user.

##### Arguments
| Name | Required? | Format |
| -----: | :----- | :----- |
| username | required | string |
| reset_email | required | string |
| **kwargs | optional | dict |

##### Example
```python
# Create an instance of ToopherIframe
api.get_user_management_url('username@yourservice.com', 'reset_email@yourservice.com')
```

### validate\_postback(data, request_token=None, **kwargs)

Verifies the authenticity of data returned from ToopherIframe by validating the cryptographic signature.

##### Arguments
| Name | Required? | Format | Default |
| -----: | :----- | :----- | :---- |
| data | required | dict | |
| request_token | optional | string | None |
| **kwargs | optional | dict | |

##### Example
```python
data = {
    'timestamp': 'timestamp',
    'session_token': 'session_token',
    'toopher_sig': 'your_toopher_sig'
}
# Create an instance of ToopherIframe
api.validate_postback(data, 'request_token')
```

# ToopherApi

### pair

Create a pairing using a pairing phrase, phone number or QR code.

```python
api.pair(username, phrase_or_num=None, **kwargs)
```

### authenticate

Initiate a login authentication request using a username or pairing ID.

```python
api.authenticate(id_or_username, terminal, action_name=None, **kwargs)
```

# Advanced - ApiRawRequester

### get

```python
api.advanced.raw.get(endpoint, **kwargs)
```

### post

```python
api.advanced.raw.post(endpoint, **kwargs)
```

# Advanced - Pairings

### get\_by\_id

Retrieve a pairing using a pairing ID.

```python
api.advanced.pairings.get_by_id(pairing_id)
```

# Advanced - AuthenticationRequests

### get\_by\_id

Retrieve an authentication request using an authentication request ID.

```python
api.advanced.authentication_requests.get_by_id(authentication_request_id)
```

# Advanced - UserTerminals

### create

Create a terminal for a user using a username.

```python
api.advanced.user_terminals.create(username, terminal_name, requester_terminal_id, **kwargs)
```

### get\_by\_id

Retrieve a terminal using a terminal ID.

```python
api.advanced.user_terminals.get_by_id(terminal_id)
```

# Advanced - Users

### create

```python
api.advanced.users.create(username, **kwargs)
```

Create user with username.

### get\_by\_id

```python
api.advanced.users.get_by_id(user_id)
```

Retrieve user by user ID.

### get\_by\_name

```python
api.advanced.users.get_by_name(username)
```

Retrieve user by user name.

# Pairing

### refresh\_from\_server

Update a pairing from server.

```python
pairing.refresh_from_server(api)
```

### get\_qr\_code\_image

Retrieve a QR code image for pairing.

```python
pairing.get_qr_code_image(api)
```

### get\_reset\_link

Retrieve a pairing reset link for a user to reset their pairing.

```python
pairing.get_reset_link(api, **kwargs)
```

### email\_reset\_link\_to\_user

Email a pairing reset link to a user.

```python
pairing.email_reset_link_to_user(api, email, **kwargs)
```

# AuthenticationRequest

### refresh\_from\_server

Update an authentication request from server.

```python
authentication_request.refresh_from_server(api)
```

### authenticate\_with\_otp

Authenticate an authentication request with a one-time password (OTP).

```python
authentication_request.authenticate_with_otp(api, otp, **kwargs)
```

# UserTerminal

### refresh\_from\_server

Update a user terminal from server.

```python
user_terminal.refresh_from_server(api)
```

# User

### refresh\_from\_server

Update a user from server.

```python
user.refresh_from_server(api)
```

### enable

Enable Toopher for a user.

```python
user.enable(api)
```

### disable

Disable Toopher for a user.

```python
user.disable(api)
```

### reset

```python
user.reset(api)
```