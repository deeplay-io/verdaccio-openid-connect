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
import {Redis} from 'ioredis';
import * as express from 'express';
import {Express} from 'express';
import {nanoid} from 'nanoid/async';
import {createPool, Pool} from 'generic-pool';

import {createRedis} from './redis';
import {URL} from 'url';

type OidcPluginConfig = {
  publicUrl: string;
  redisUri: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  usernameClaim?: string;
};

export default class OidcPlugin
  implements IPluginAuth<OidcPluginConfig>, IPluginMiddleware<OidcPluginConfig>
{
  private redis!: Redis;
  private redisPool!: Pool<Redis>;
  private clientPromise!: Promise<Client>;
  private closed = false;
  private logger!: Logger;

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

    this.redis = createRedis(options.config.redisUri);

    this.redisPool = createPool<Redis>(
      {
        async create() {
          const redis = createRedis(options.config.redisUri);
          await redis.connect();

          return redis;
        },
        async destroy(redis) {
          await redis.quit();
        },
      },
      {
        min: 0,
        max: 1000,
        evictionRunIntervalMillis: 10_000,
        acquireTimeoutMillis: 10_000,
      },
    );

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

    this.redis.quit();

    this.redisPool.drain();
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

  private async saveSession(
    sessionId: string,
    tokenSet: TokenSet,
  ): Promise<void> {
    await this.redis.set(
      `session:${sessionId}`,
      JSON.stringify(tokenSet),
      'EX',
      60 * 60 * 24 * 30, // 1 month
    );
  }

  authenticate(user: string, password: string, cb: AuthCallback): void {
    Promise.resolve()
      .then(async () => {
        const sessionId = password;
        const sessionStr = await this.redis.get(`session:${sessionId}`);

        if (sessionStr == null) {
          cb(null, false);
          return;
        }

        const tokenSet = new TokenSet(JSON.parse(sessionStr));

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

          const refreshedTokenSet = await client.refresh(tokenSet);

          await this.saveSession(sessionId, refreshedTokenSet);
        }

        this.logger.info({username}, 'Authenticated @{username}');

        cb(null, [username]);
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
            scope: 'openid email profile',
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

          await this.redis.xadd(
            `login:${loginRequestId}`,
            '*',
            'token',
            npmToken,
          );
          await this.redis.expire(`login:${loginRequestId}`, 60 * 60);

          res.set('Content-Type', 'text/html').end(callbackResponseHtml);
        })
        .catch(next);
    });

    app.get('/oidc/done/:loginRequestId', (req, res, next) => {
      Promise.resolve()
        .then(async () => {
          const result = await this.redisPool.use(redis =>
            redis.xread(
              'BLOCK',
              10_000,
              'STREAMS',
              `login:${req.params.loginRequestId}`,
              '0-0',
            ),
          );

          if (result == null || result.length === 0) {
            res.status(202).end(JSON.stringify({}));
            return;
          }

          const token = result[0][1][0][1][1]; // omg sorry

          res
            .set('Content-Type', 'application/json')
            .end(JSON.stringify({token}));
        })
        .catch(next);
    });
  }
}

const callbackResponseHtml = `
<!DOCTYPE html>
<html>
  <head>
  </head>
  <body>
    You may close this page now.
    <script>setTimeout(function() {window.close()}, 0)</script>
  </body>
</html>
`;
