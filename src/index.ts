import {
  IBasicAuth,
  IPluginMiddleware,
  IPluginAuth,
  AuthCallback,
  Config,
  PluginOptions,
  Logger,
} from '@verdaccio/types';
import {Issuer, Client, TokenSet} from 'openid-client';
import asyncRetry = require('async-retry');
import * as express from 'express';
import {Express} from 'express';
import {nanoid} from 'nanoid/async';

import {URL} from 'url';

import { ISessionStorage, ITokenStorage } from './types';
import { NewRedisStorage } from './redis';
import { NewFileStorage } from './fs';

type OidcPluginConfig = {
  publicUrl: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  usernameClaim?: string;
  rolesClaim?: string;

  redisUri?: string;
  fsSessionStorePath?: string
  fsTokenStorePath?: string;
};

export default class OidcPlugin
  implements IPluginAuth<OidcPluginConfig>, IPluginMiddleware<OidcPluginConfig>
{
  private clientPromise!: Promise<Client>;
  private closed = false;
  private logger!: Logger;
  private ss!: ISessionStorage;
  private ts!: ITokenStorage;

  constructor(
    config: OidcPluginConfig & Config,
    private options: PluginOptions<OidcPluginConfig>,
  ) {
    if (options.config.oidcPluginInstance != null) {
      return options.config.oidcPluginInstance;
    }

    options.config.middlewares = {
      ...options.config.middlewares,
      'openid-connect': {oidcPluginInstance: this},
    };

    this.logger = options.logger;

    if (options.config.redisUri) {
      const rs = NewRedisStorage(options.config.redisUri);
      this.ss = rs.ss;
      this.ts = rs.ts;
    } else if (options.config.fsSessionStorePath && options.config.fsTokenStorePath) {
      const rs = NewFileStorage(this.logger, options.config.fsSessionStorePath, options.config.fsTokenStorePath);
      this.ss = rs.ss;
      this.ts = rs.ts;
    } else {
      throw new Error('invalid configuration: none of [redisUri] or [fsSessionStorePath, fsTokenStorePath] is set');
    }

    this.clientPromise = asyncRetry(
      () => Issuer.discover(options.config.issuer),
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
          client_id: options.config.clientId,
          client_secret: options.config.clientSecret,
          redirect_uris: [
            new URL('oidc/callback', options.config.publicUrl).toString(),
          ],
          response_types: ['code'],
        }),
    );
  }

  close() {
    if (this.closed) {
      return;
    }

    this.closed = true;

    this.ss.close();
    this.ts.close();
  }

  private getUsername(tokenSet: TokenSet): string {
    const {usernameClaim = 'preferred_username'} = this.options.config;

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
    const {rolesClaim} = this.options.config;
    if (!rolesClaim) {
      return [];
    }

    let roles: any = tokenSet.claims()[rolesClaim];
    if (typeof roles === 'string') {
      roles = roles.split(',').map((x:string) => x.trim());
    }

    if (!Array.isArray(roles)) {
      throw new Error(
        `Missing roles claim '${rolesClaim}'. Available claims: ${JSON.stringify(
          Object.keys(tokenSet.claims()),
        )}`,
      );
    }

    return roles;
  }

  private async saveSession(
    sessionId: string,
    tokenSet: TokenSet,
  ): Promise<void> {
    await this.ss.set(
        `session:${sessionId}`,
        tokenSet,
        60 * 60 * 24 * 30, // 1 month
    );
  }

  authenticate(user: string, password: string, cb: AuthCallback): void {
    Promise.resolve()
      .then(async () => {
        const sessionId = password;
        const tokenSetObj: any|null = await this.ss.get(`session:${sessionId}`);

        if (tokenSetObj == null) {
          cb(null, false);
          return;
        }

        let tokenSet = new TokenSet(tokenSetObj);

        const username = this.getUsername(tokenSet);

        if (username !== user) {
          this.logger.error(
            {user, username},
            'Rejecting auth because username @{user} does not match session username @{username}',
          );
          cb(null, false);
          return;
        }

        if (tokenSet.expired()) {
          this.logger.info(
            {username},
            'Refreshing expired session for @{username}',
          );

          const client = await this.clientPromise;

          tokenSet = await client.refresh(tokenSet);

          await this.saveSession(sessionId, tokenSet);
        }

        const roles = this.getRoles(tokenSet);

        this.logger.info({username}, 'Authenticated @{username}');

        cb(null, [username, ...roles]);
      })
      .catch(err => cb(err, false));
  }

  register_middlewares(app: Express, auth: IBasicAuth<OidcPluginConfig>): void {
    app.post('/-/v1/login', express.json(), (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const loginRequestId = await nanoid();

          res.set('Content-Type', 'application/json').end(
            JSON.stringify({
              loginUrl: new URL(
                `oidc/login/${loginRequestId}`,
                this.options.config.publicUrl,
              ),
              doneUrl: new URL(
                `oidc/done/${loginRequestId}`,
                this.options.config.publicUrl,
              ),
            }),
          );
        })
        .catch(next);
    });

    app.get('/oidc/login/:loginRequestId', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const client = await this.clientPromise;

          const authorizationUrl = client.authorizationUrl({
            scope: this.options.config.scope || 'openid email profile',
            state: req.params.loginRequestId,
            redirect_uri: new URL(
              'oidc/callback',
              this.options.config.publicUrl,
            ).toString(),
          });

          res.redirect(authorizationUrl);
        })
        .catch(next);
    });

    app.get('/oidc/callback', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const client = await this.clientPromise;

          const params = client.callbackParams(req);

          const tokenSet = await client.callback(
            new URL('oidc/callback', this.options.config.publicUrl).toString(),
            params,
            {
              state: params.state,
              nonce: null!,
            },
          );

          const loginRequestId = params.state;
          const sessionId = await nanoid();

          await this.saveSession(sessionId, tokenSet);

          const username = this.getUsername(tokenSet);

          const npmToken = auth
            .aesEncrypt(Buffer.from(`${username}:${sessionId}`, 'utf8'))
            .toString('base64');

          await this.ts.set(`login:${loginRequestId}`, npmToken, 5 * 60);

          res.set('Content-Type', 'text/html').end(callbackResponseHtml(npmToken));
        })
        .catch(next);
    });

    app.get('/oidc/done/:loginRequestId', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const token = await this.ts.get(`login:${req.params.loginRequestId}`, 10_000);

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
}

const callbackResponseHtml = (token: string)=>`
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    <script>
      localStorage.setItem('token', ${JSON.stringify(token)});
    </script>
    You may close this page now.
    <script>setTimeout(function() {window.close()}, 0)</script>
  </body>
</html>
`;
