Toopher API
===

1. ToopherIframe
    * [get\_user\_management\_url](#get\_user\_management\_url)
    * [get\_auth\_url](#get\_auth\_url)
    * [validate\_postback](#validate\_postback)

2. ToopherApi
    * [pair](#pair)
    * [get\_pairing\_by\_id](#get\_pairing\_by\_id)
    * [authenticate](#authenticate)
    * [get\_authentication\_request\_by\_id](#get\_authentication\_request\_by\_id)
    * [create\_user](#create\_user)
    * [reset\_user](#reset\_user)
    * [get\_user\_by\_id](#get\_user\_by\_id)
    * [create\_user\_terminal](#create\_user\_terminal)
    * [get\_user\_terminal\_by\_id](#get\_user\_terminal\_by\_id)
    * [enable\_user](#enable\_user)
    * [disable\_user](#disable\_user)
    * [get\_pairing\_reset\_link](#get\_pairing\_reset\_link)
    * [email\_pairing\_reset\_link\_to\_user](#email\_pairing\_reset\_link\_to\_user)
    * [get](#get)
    * [post](#post)

3. Pairing
    * [refresh\_from\_server](#refresh\_from\_server)
    * [get\_qr\_code\_image](#get\_qr\_code\_image)

4. AuthenticationRequest
    * [refresh\_from\_server](#refresh\_from\_server)
    * [authenticate\_with\_otp](#authenticate\_with\_otp)

5. UserTerminal
    * [refresh\_from\_server](#refresh\_from\_server)

6. User
    * [refresh\_from\_server](#refresh\_from\_server)
    * [enable](#enable)
    * [disable](#disable)
    * [reset](#reset)


# ToopherIframe

## get\_user\_management\_url

```python
api.get_user_management_iframe_url(username, reset_email, **kwargs)
```

Retrieve OAuth-signed pairing IFrame URL.

## get\_auth\_url

```python
api.get_auth_iframe_url(username, reset_email, request_token, action_name='Log In', requester_metadata='None', **kwargs)
```

Retrieve OAuth-signed combined pairing/authentication IFrame URL.

## validate\_postback

```python
api.validate_postback((data, request_token=None, **kwargs)
```

Validate authentication request from IFrame.

# ToopherApi

## pair

```python
api.pair(username, phrase_or_num=None, **kwargs)
```

Pairing using pairing phrase, phone number or QR code.

## get\_pairing\_by\_id

```python
api.get_pairing_by_id(pairing_id)
```

Retrieve pairing by pairing ID.

## authenticate

```python
api.authenticate(id_or_username, terminal, action_name=None, **kwargs)
```

Authenticate pairing with username or pairing ID.

## get\_authentication\_request\_by\_id

```python
api.get_authentication_request_by_id(authentication_request_id)
```

Retrieve authentication request by authentication request ID.

## create\_user

```python
api.create_user(username, **kwargs)
```

Create user with username.

## reset\_user

```python
api.reset_user(username)
```

Reset user with username.

## get\_user\_by\_id

```python
api.get_user_by_id(user_id)
```

Retrieve user by user ID.

## create\_user\_terminal

```python
api.create_user_terminal(username, terminal_name, requester_terminal_id, **kwargs)
```

Create terminal for user with username.

## get\_user\_terminal\_by\_id

```python
api.get_user_terminal_by_id(terminal_id)
```

Retrieve terminal by terminal ID.

## enable\_user

```python
api.enable_user(username)
```

Enable Toopher for user by username.

## disable\_user

```python
api.disable_user(username)
```

Disable Toopher for user by username.

## get\_pairing\_reset\_link

```python
api.get_pairing_reset_link(pairing_id, **kwargs)
```

Retrieve pairing reset link for user to reset their pairing.

## email\_pairing\_reset\_link\_to\_user

```python
api.email_pairing_reset_link_to_user(pairing_id, email, **kwargs)
```

Email pairing reset link to user.

## get

```python
api.get(endpoint, **kwargs)
```

## post

```python
api.post(endpoint, **kwargs)
```

# Pairing

## refresh\_from\_server

```python
pairing.refresh_from_server(api)
```

Update pairing from server.

## get\_qr\_code\_image

```python
pairing.get_qr_code_image(api)
```

Retrieve QR code image for pairing.

# AuthenticationRequest

## refresh\_from\_server

```python
authentication_request.refresh_from_server(api)
```

Update authentication request from server.

## authenticate\_with\_otp

```python
authentication_request.authenticate_with_otp(otp, api, **kwargs)
```

Authenticate authentication request with one-time password (OTP).

# UserTerminal

## refresh\_from\_server

```python
user_terminal.refresh_from_server(api)
```

Update user terminal from server.

# User

## refresh\_from\_server

```python
user.refresh_from_server(api)
```

Update user from server.

## enable

```python
user.enable(api)
```

Enable Toopher for the user.

## disable

```python
user.disable(api)
```

Disable Toopher for the user.

## reset

```python
user.reset(api)
```