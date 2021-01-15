# verdaccio-oidc

Verdaccio authentication plugin for OpenID Connect.

## Installation

    npm i -g verdaccio-oidc

## Configuration

```yaml
auth:
  oidc:
    # Verdaccio public url
    publicUrl: http://localhost:4873
    # Redis hostname
    redisUri: redis
    # OpenID Connect Issuer URL
    issuer: https://keycloak/auth/realms/MyRealm/
    # OpenID Connect Client ID
    clientId: verdaccio
    # OpenID Connect Client Secret
    clientSecret: '...'
    # Optional id_token claim that will be used for username
    usernameClaim: preferred_username
```

OpenID Connect Client must be configured to allow `${publicUrl}/oidc/callback`
as a redirect URI.
