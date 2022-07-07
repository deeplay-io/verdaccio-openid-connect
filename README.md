# verdaccio-openid-connect

Verdaccio authentication plugin for OpenID Connect. When installed, `npm login --registry ...` command will open the browser to start login flow.

Compatible with Verdaccio 4.x and 5.x.

## Installation

    npm i -g verdaccio-openid-connect

## Configuration

```yaml
auth:
  openid-connect:
    # Verdaccio public URL. If served on a subpath, make sure to include a
    # trailing slash.
    publicUrl: http://localhost:4873/
    # Redis hostname
    # When set redis storage (for sessions and tokens) will be used.
    # see also: fsSessionStorePath, fsTokenStorePath.
    redisUri: redis
    # Session files (persistent) storage path and token files (temporary for short-lived files) storage path: will be used if redisUri not set
    #fsSessionStorePath: /tmp
    #fsTokenStorePath: /tmp
    # OpenID Connect Issuer URL
    issuer: https://keycloak/auth/realms/MyRealm/
    # OpenID Connect Client ID
    clientId: verdaccio
    # OpenID Connect Client Secret
    clientSecret: '...'
    # OpenID Connect Scopes
    scope: openid profile email offline_access
    # Optional id_token claim that will be used for username
    usernameClaim: preferred_username
```

OpenID Connect Client must be configured to allow `${publicUrl}/oidc/callback`
as a redirect URI.
