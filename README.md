#Welcome to the WSO2 Identity Server Token Exchange Grant Type for OAuth2. 

This repository contains implementation for the OAuth 2.0 Token Exchange Grant, described in [spec](https://datatracker.ietf.org/doc/html/rfc8693).
You can exchange external Identity Provider's token for the token issued by Identity Server. The initial implementation supports exchanging JWT type tokens.

##How to test Token Exchange Grant Type:

* Register an Identity Provider in WSO2 Identity Server with the configurations of the external Identity Provider.
* Obtain an access token from external Identity Provider
* Execute the following curl command:

```curl
curl --location --request POST 'https://localhost:9443/oauth2/token?scope=openid' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic ${base64(clientId:clientSecret)}' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
--data-urlencode 'subject_token=${externalIdPToken}' \
--data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
--data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:jwt'
``` 

* You will get JWT type access token in the response. Sample response:

```json
{
    "access_token": "eyJ4NXQiOiJPVGt3TnpSa01tTmxZekZoWWpFeU56VTNOemN3TjJZNU9EQmpNV1kzTTJJMk1EZGhabUU1TmpCbE1qRmtaR0kxTkdFNU9XVTRPREU0TlRCaE1EWXhZUSIsImtpZCI6Ik9Ua3dOelJrTW1ObFl6RmhZakV5TnpVM056Y3dOMlk1T0RCak1XWTNNMkkyTURkaFptRTVOakJsTWpGa1pHSTFOR0U1T1dVNE9ERTROVEJoTURZeFlRX1JTMjU2IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJ0ZXN0QGdtYWlsLmNvbSIsImF1dCI6IkFQUExJQ0FUSU9OX1VTRVIiLCJhdWQiOiJYdllmNDI5M2FLX19PNkdXUXV4MDMxZ0VxRUVhIiwibmJmIjoxNjIzMTUyNDQ0LCJhenAiOiJYdllmNDI5M2FLX19PNkdXUXV4MDMxZ0VxRUVhIiwic2NvcGUiOiJkZWZhdWx0IiwiaXNzIjoiaHR0cHM6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3Rva2VuIiwiZXhwIjoxNjIzMTU2MDQ0LCJpYXQiOjE2MjMxNTI0NDQsImp0aSI6IjZmZjJjY2FmLWEzNGMtNDYzZi04MTUxLTUxMDNlNzNkNTljMSJ9.BOxQeP3ZZgckIHazM79AFRdy1-S2ntaCzEDQLQwSQjswuaXHesNARVKrwuyw8v7IJXF_7zFglpF2d9PfoTNwjgpJStW_d-n_1NOUr5eyMU0Y5zHDwOFFKrV51WpV99L1KWZbLwiN_kvUbpVDvTijyNDK29cHxQHak6TqUeqDJfVW92bOAqrp88Rn3h19YRlEttjpPrepKDFJ1lse7gO1NO--87pJpwjWEaniQrNNuB1GDbVXYOLWp5ql-X5w9PrJtnrtbska6sAuURScNL0MpLdB4QiO1cMLVyIedwPotv04qeX80ATv9KOlEkoG2ycNHCmW0iHHspn5HtPyTZxxYg",
    "refresh_token": "7f3bf5df-feb2-356b-a3fb-0a3fc499bf1e",
    "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "scope": "default",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### Related Configurations:




