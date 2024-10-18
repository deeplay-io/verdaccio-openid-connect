# verdaccio-openid-connect

Verdaccio authentication plugin for OpenID Connect. When installed,
`npm login --registry ...` command will open the browser to start login flow.

Compatible with Verdaccio 4.x, 5.x and 6.x.

## Installation

    npm i -g verdaccio-openid-connect

## Configuration

See sample configuration in [./config.yaml](config.yaml).

Note: OpenID Connect Client must be configured to allow `${publicUrl}/oidc/callback` as a redirect URI.
