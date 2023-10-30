import {
  IBasicAuth,
  IPluginMiddleware,
  IPluginAuth,
  AuthCallback,
  PluginOptions,
  Logger,
  RemoteUser,
  JWTSignOptions,
} from '@verdaccio/types';
import {Issuer, Client, TokenSet} from 'openid-client';
import asyncRetry = require('async-retry');
import * as express from 'express';
import {Express, Response} from 'express';
import {nanoid} from 'nanoid/async';
import ms = require('ms');
import * as jwt from 'jsonwebtoken';
import {URL} from 'url';

import {ISessionStorage, ITokenStorage} from './types';
import {NewRedisStorage} from './redis';
import {NewFileStorage} from './fs';

type OidcPluginConfig = {
  publicUrl: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  usernameClaim?: string;
  rolesClaim?: string;

  redisUri?: string;
  fsSessionStorePath?: string;
  fsTokenStorePath?: string;

  accessTokenAuth?: boolean;

  oidcPluginInstance: OidcPlugin;
};

type Tokens = {
  npmToken: string;
  webToken: string;
};

type RemoteUserEx = RemoteUser & {sid: string};

enum PluginMode {
  LEGACY,
  JWT,
}

const UnsupportedPluginModeError = () => new Error('unsupported plugin mode');
const TOKEN_BEARER = 'Bearer';

export default class OidcPlugin
  implements IPluginAuth<OidcPluginConfig>, IPluginMiddleware<OidcPluginConfig>
{
  private readonly pluginName = 'verdaccio-openid-connect';

  private config: OidcPluginConfig;
  private options: PluginOptions<OidcPluginConfig>;
  private clientPromise!: Promise<Client>;
  private closed = false;
  private logger!: Logger;
  private ss!: ISessionStorage;
  private ts!: ITokenStorage;
  private mode!: PluginMode;
  private sessionTtl!: number;

  constructor(
    config: OidcPluginConfig,
    options: PluginOptions<OidcPluginConfig>,
  ) {
    this.config = config;
    this.options = options;
    if (this.config.oidcPluginInstance != null) {
      return this.options.config.oidcPluginInstance;
    }
    
    this.options.config.middlewares = {
      ...options.config.middlewares,
      'openid-connect': {oidcPluginInstance: this},
    };
    this.logger = options.logger;

    if (this.options.config.security?.api?.legacy) {
      // Legacy property means that explicitly you want to use the legacy token system signature.
      // You might not like to do not remove the whole security section in order to disable JWT
      // and for such reason, this property exists.
      this.mode = PluginMode.LEGACY;
    } else {
      this.mode = this.options.config.security?.api?.jwt
        ? PluginMode.JWT
        : PluginMode.LEGACY;
    }

    switch (this.mode) {
      case PluginMode.LEGACY:
        this.logger.trace(
          {pluginName: this.pluginName},
          '@{pluginName} in legacy mode',
        );
        this.apiJWTmiddleware = undefined;
        this.sessionTtl = ms('30d');
        break;
      case PluginMode.JWT:
        this.logger.trace(
          {pluginName: this.pluginName},
          '@{pluginName} in jwt mode',
        );
        this.apiJWTmiddleware = this._apiJWTmiddleware;
        const sessionExpiresIn =
          this.options.config.security?.api?.jwt?.sign?.expiresIn;
        const sessionTtl =
          sessionExpiresIn == null || sessionExpiresIn === 'never'
            ? '30d'
            : sessionExpiresIn;
        this.sessionTtl = Number.isNaN(+sessionTtl)
          ? ms(sessionTtl)
          : +sessionTtl;
        break;
      default:
        throw UnsupportedPluginModeError();
    }

    if (this.config.redisUri) {
      const rs = NewRedisStorage(this.config.redisUri);
      this.ss = rs.ss;
      this.ts = rs.ts;
    } else if (
      this.config.fsSessionStorePath &&
      this.config.fsTokenStorePath
    ) {
      const rs = NewFileStorage(
        this.logger,
        this.config.fsSessionStorePath,
        this.config.fsTokenStorePath,
      );
      this.ss = rs.ss;
      this.ts = rs.ts;
    } else {
      throw new Error(
        'invalid configuration: none of [redisUri] or [fsSessionStorePath, fsTokenStorePath] is set',
      );
    }

    this.clientPromise = asyncRetry(
      () => Issuer.discover(this.config.issuer),
      {
        forever: true,
        maxTimeout: 30_000,
        onRetry: (err, attempt) => {
          this.logger.error(
            {err, attempt},
            'Failed to discover issuer, retrying [@{attempt}]: @{!err.message}\n@{err.stack}',
          );
        },
      },
    ).then(
      issuer =>
        new issuer.Client({
          client_id: this.config.clientId,
          client_secret: this.config.clientSecret,
          redirect_uris: [
            new URL('oidc/callback', this.config.publicUrl).toString(),
          ],
          response_types: ['code'],
        }),
    );
  }

  public close() {
    let plugin = this.getInstance();
    if (plugin.closed) {
      return;
    }

    plugin.closed = true;
    plugin.ss.close();
    plugin.ts.close();
  }

  private getInstance(): OidcPlugin {
    if ('oidcPluginInstance' in this.config) {
      return this.config.oidcPluginInstance;
    } else if ('clientPromise' in this) {
      return this;
    } else {
      throw new Error(`Unable to find plugin instance. This = ${JSON.stringify(this)}`);
    }
  }

  private getUsername(tokenSet: TokenSet): string {
    let plugin = this.getInstance();

    const {usernameClaim = 'preferred_username'} = plugin.config;
    const username = tokenSet.claims()[usernameClaim];

    if (typeof username !== 'string') {
      throw new Error(
        `Missing username claim '${usernameClaim}'. Available claims: ${JSON.stringify(
          Object.keys(tokenSet.claims()),
        )}`,
      );
    }
    return username;
  }

  private getRoles(tokenSet: TokenSet): string[] {
    let plugin = this.getInstance();

    const {rolesClaim} = plugin.config;
    if (!rolesClaim) {
      return [];
    }

    let roles: any = tokenSet.claims()[rolesClaim];
    if (typeof roles === 'string') {
      roles = roles.split(',').map((x: string) => x.trim());
    }
    if (!Array.isArray(roles)) {
      // oidc server can exlude roles claim from token if its length == 0
      plugin.logger.info(
        {rolesClaim, claims: JSON.stringify(Object.keys(tokenSet.claims()))},
        `Missing roles claim '@{rolesClaim}. Available claims: @{claims}'`,
      );
      return [];
    }
    return roles;
  }

  private async saveSession(
    sessionId: string,
    tokenSet: TokenSet,
  ): Promise<void> {
    let plugin = this.getInstance();
    return plugin.ss.set(`session:${sessionId}`, tokenSet, plugin.sessionTtl);
  }

  public authenticate(user: string, password: string, cb: AuthCallback): void {
    let plugin = this.getInstance();

    Promise.resolve()
      .then(async () => {
        const sessionId = password;
        const tokenSetObj: any | null = await plugin.ss.get(
          `session:${sessionId}`,
        );
        if (tokenSetObj == null) {
          cb(null, false);
          return;
        }

        let tokenSet = new TokenSet(tokenSetObj);
        const username = this.getUsername(tokenSet);

        if (username !== user) {
          plugin.logger.error(
            {user, username},
            'Rejecting auth because username @{user} does not match session username @{username}',
          );
          cb(null, false);
          return;
        }
        if (tokenSet.expired()) {
          plugin.logger.info(
            {username},
            'Refreshing expired session for @{username}',
          );

          const client = await plugin.clientPromise;
          tokenSet = await client.refresh(tokenSet);
          await this.saveSession(sessionId, tokenSet);
        }

        plugin.logger.info({username}, 'Authenticated @{username}');

        const roles = this.getRoles(tokenSet);
        cb(null, [username, ...roles]);
      })
      .catch(err => cb(err, false));
  }

  public apiJWTmiddleware?: (helpers: any) => any;

  private _apiJWTmiddleware(helpers: any): any {
    let plugin = this.getInstance();

    return (
      req: express.Request & {remote_user: RemoteUserEx},
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      req.pause();

      const next = function (err?: Error) {
        req.resume(); // uncomment this to reject users with bad auth headers
        // return _next.apply(null, arguments)
        // swallow error, user remains unauthorized
        // set remoteUserError to indicate that user was attempting authentication

        if (err) {
          req.remote_user.error = err.message;
        }

        return _next();
      };

      if (req.remote_user?.name) {
        return next();
      }

      req.remote_user = helpers.createAnonymousRemoteUser();

      const {authorization} = req.headers;
      if (!authorization) {
        // looks like this is anonymous query - pass req to verdaccio core
        return next();
      }

      const authorizationParts = authorization.split(' ', 2);
      if (
        authorizationParts.length !== 2 ||
        authorizationParts[0] !== TOKEN_BEARER
      ) {
        plugin.logger.warn(
          {scheme: authorizationParts[0]},
          'unsupported authorization encoding or scheme @{scheme}',
        );
        return next(new Error('unsupported authorization encoding or scheme'));
      }

      const jwtRaw = authorizationParts[1];
      let jwtPayload = undefined;

      try {
        jwtPayload = jwt.verify(jwtRaw, plugin.options.config.secret);
      } catch (err) {
        plugin.logger.error(
          {err},
          'erro while verify jwt bearer token: @{!err.message}\n@{err.stack}',
        );
      }

      if (!jwtPayload) {
        return next(new Error('unable to verify jwt bearer token'));
      }

      const {sid, name, real_groups} = jwtPayload as RemoteUserEx;
      if (!sid) {
        plugin.logger.error({}, 'income jwt token not contains [sid] claim');
        return next(new Error('jwt token not contains sid'));
      }
      if (!name) {
        plugin.logger.error({}, 'income jwt token not contains [name] claim');
        return next(new Error('jwt token not contains name'));
      }
      if (!real_groups) {
        plugin.logger.error(
          {},
          'income jwt token not contains [real_groups] claim',
        );
        return next(new Error('jwt token not contains real_groups'));
      }

      this.authenticate(name, sid, (err, groups) => {
        if (err) {
          plugin.logger.error({err}, 'auth error: @{!err.message}\n@{err.stack}');
          return next(err);
        }
        if (!groups) {
          plugin.logger.error(
            {sid},
            'unable to found session groups for income jwt token session @{sid}',
          );
          return next(
            new Error(
              'unable to found session groups for income jwt token session',
            ),
          );
        }

        const groupsWithoutUser: string[] = groups.slice(1);
        const {rolesClaim} = plugin.config;
        if (rolesClaim) {
          if (!real_groups.every(v => groupsWithoutUser.includes(v))) {
            plugin.logger.error(
              {},
              'income token contains [real_groups] claim that not subset of oidc server roles claim',
            );
            return next(
              new Error(
                'income token contains [real_groups] claim that not subset of oidc server roles claim',
              ),
            );
          }
        }

        req.remote_user = helpers.createRemoteUser(name, groupsWithoutUser);
        next();
      });
    };
  }

  public register_middlewares(
    app: Express,
    auth: IBasicAuth<OidcPluginConfig>,
  ): void {
    let plugin = this.getInstance();
    app.put(
      '/-/user/org.couchdb.user::userId',
      express.json(),
      (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            const subjectToken = req.body.password;
            if (!subjectToken) {
              this.unauthorized(res, 'Password attribute is missing.');
              return;
            }
            const userName = req.body.name;
            if (userName !== req.params[':userId']) {
              this.unauthorized(res, 'User ID in URL and body do not match.');
              return;
            }
            const clientSecret = plugin.config.clientSecret;
            const clientId = plugin.config.clientId;
            const client = await plugin.clientPromise;
            let tokenSet = await client.grant({
              grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
              'requested_token_type ':
                'urn:ietf:params:oauth:token-type:refresh_token',
              client_secret: clientSecret,
              client_id: clientId,
              subject_token: subjectToken,
              subject_token_type:
                'urn:ietf:params:oauth:token-type:access_token',
              scope: plugin.config.scope,
            });

            const tokenUsername = this.getUsername(tokenSet);
            if (userName !== tokenUsername) {
              this.unauthorized(
                res,
                'Access token is not issued for the user trying to log in.',
              );
              return;
            }

            const sessionId = await nanoid();
            const {npmToken} = await this.saveSessionAndCreateTokens(
              sessionId,
              tokenSet,
              auth,
            );
            const responseBody = JSON.stringify({token: npmToken});
            res.status(201);
            res.set('Content-Type', 'application/json').end(responseBody);
          })
          .catch(next);
      },
    );

    if (plugin.config.accessTokenAuth !== true) {
      app.post('/-/v1/login', express.json(), (req, res, next) => {
        Promise.resolve()
          .then(async () => {
            const loginRequestId = await nanoid();

            res.set('Content-Type', 'application/json').end(
              JSON.stringify({
                loginUrl: new URL(
                  `oidc/login/${loginRequestId}`,
                  plugin.config.publicUrl,
                ),
                doneUrl: new URL(
                  `oidc/done/${loginRequestId}`,
                  plugin.config.publicUrl,
                ),
              }),
            );
          })
          .catch(next);
      });
    }

    app.get('/oidc/login/:loginRequestId', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const client = await plugin.clientPromise;

          const authorizationUrl = client.authorizationUrl({
            scope: plugin.config.scope || 'openid email profile',
            state: req.params.loginRequestId,
            redirect_uri: new URL(
              'oidc/callback',
              plugin.config.publicUrl,
            ).toString(),
          });

          res.redirect(authorizationUrl);
        })
        .catch(next);
    });

    app.get('/oidc/callback', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const client = await plugin.clientPromise;
          const params = client.callbackParams(req);

          const tokenSet = await client.callback(
            new URL('oidc/callback', plugin.config.publicUrl).toString(),
            params,
            {
              state: params.state,
              nonce: null!,
            },
          );

          const loginRequestId = params.state;
          const sessionId = await nanoid();
          const {npmToken, webToken} = await this.saveSessionAndCreateTokens(
            sessionId,
            tokenSet,
            auth,
          );

          await plugin.ts.set(`login:${loginRequestId}`, npmToken, 5 * 60);
          res
            .set('Content-Type', 'text/html')
            .end(callbackResponseHtml(this.getUsername(tokenSet), webToken));
        })
        .catch(next);
    });

    app.get('/oidc/done/:loginRequestId', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const token = await plugin.ts.get(
            `login:${req.params.loginRequestId}`,
            10_000,
          );

          if (token == null) {
            res.status(202).end(JSON.stringify({}));
            return;
          }

          res
            .set('Content-Type', 'application/json')
            .end(JSON.stringify({token}));
        })
        .catch(next);
    });
  }

  private unauthorized(res: Response, msg: string): void {
    let plugin = this.getInstance();
    plugin.logger.trace({msg}, 'Unauthorized access: @{msg}');
    res.status(401);
    res.set('Content-Type', 'text/plain').end(msg);
  }

  private async saveSessionAndCreateTokens(
    sessionId: string,
    tokenSet: TokenSet,
    auth: IBasicAuth<OidcPluginConfig>,
  ): Promise<Tokens> {
    let plugin = this.getInstance();

    await this.saveSession(sessionId, tokenSet);
    const username = this.getUsername(tokenSet);
    const userroles = this.getRoles(tokenSet);

    let npmToken: string;
    let webToken: string;
    switch (plugin.mode) {
      case PluginMode.LEGACY:
        npmToken = auth
          .aesEncrypt(Buffer.from(`${username}:${sessionId}`, 'utf8'))
          .toString('base64');
        webToken = npmToken;
        break;
      case PluginMode.JWT:
        const rUser = {
          ...createRemoteUser(username, userroles),
          sid: sessionId,
        };
        npmToken = await signPayload(rUser, auth.config.secret, {
          expiresIn: this.options.config.security?.api?.jwt?.sign?.expiresIn,
        });
        webToken = await signPayload(rUser, auth.config.secret, {
          // default expiration for web tokens is 7 days:
          // https://github.com/verdaccio/verdaccio/blob/64f0921477ef68fc96a2327c7a3c86a45f6d0255/packages/config/src/security.ts#L5-L11
          expiresIn: this.options.config.security?.web?.sign?.expiresIn ?? '7d',
        });
        break;
      default:
        throw UnsupportedPluginModeError();
    }
    return {npmToken, webToken};
  }
}

function createRemoteUser(name: string, pluginGroups: string[]): RemoteUser {
  //copy&paste from: verdaccio/src/lib/auth-utils.ts
  const isGroupValid: boolean = Array.isArray(pluginGroups);
  const groups = (isGroupValid ? pluginGroups : []).concat([
    '$all',
    'all',
    '$authenticated',
    '@all',
    '@authenticated',
  ]);

  return {
    name,
    groups,
    real_groups: pluginGroups,
  };
}

function signPayload(
  payload: RemoteUserEx,
  secretOrPrivateKey: string,
  options: JWTSignOptions,
): Promise<string> {
  // copy&paste from verdaccio/src/lib/crypto-utils.ts
  const opts: any = {
    notBefore: '1', // Make sure the time will not rollback :)
    ...options,
  };
  return new Promise(function (resolve, reject) {
    jwt.sign(payload, secretOrPrivateKey, opts, (error: any, token: any) =>
      error ? reject(error) : resolve(token),
    );
  });
}

const callbackResponseHtml = (username: string, token: string) => `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <script>
      localStorage.setItem('username', ${JSON.stringify(username)});
      localStorage.setItem('token', ${JSON.stringify(token)});
    </script>
    You are now authenticated in npm and on this website. You may close this page now.
    <script>setTimeout(function() {window.close()}, 0)</script>
  </body>
</html>
`;
