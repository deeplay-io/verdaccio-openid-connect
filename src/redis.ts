import IORedis = require('ioredis');
import {ISessionStorage, ITokenStorage} from './types';
import {Redis} from 'ioredis';
import {createPool, Pool} from 'generic-pool';

export function NewRedisStorage(redisUri: string): {
  ss: ISessionStorage;
  ts: ITokenStorage;
} {
  const redis = createRedis(redisUri);

  const redisPool = createPool<Redis>(
    {
      async create() {
        const redis = createRedis(redisUri);
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

  let closed = false;
  const closeFn = () => {
    if (closed) return Promise.resolve();
    closed = true;

    redis.quit();
    redisPool.drain();
    return Promise.resolve();
  };

  return {
    ss: new RedisSessionStorage(redis, redisPool, closeFn),
    ts: new RedisTokenStorage(redis, redisPool, closeFn),
  };
}

class RedisTokenStorage implements ITokenStorage {
  constructor(
    private redis: Redis,
    private redisPool: Pool<Redis>,
    private fnClose: () => Promise<void>,
  ) {}

  public close(): Promise<void> {
    return this.fnClose();
  }

  public async set(
    key: string,
    value: any,
    expires_sec: number,
  ): Promise<void> {
    await this.redis.xadd(key, '*', 'token', value);
    await this.redis.expire(key, expires_sec);
  }

  public async tryGet(key: string, timeout: number): Promise<any | null> {
    const result = await this.redisPool.use(redis =>
      redis.xread('BLOCK', timeout, 'STREAMS', key, '0-0'),
    );

    if (result == null || result.length === 0) {
      return null;
    }

    return result[0][1][0][1][1]; // omg sorry
  }
}

class RedisSessionStorage implements ISessionStorage {
  constructor(
    private redis: Redis,
    _redisPool: Pool<Redis>,
    private fnClose: () => Promise<void>,
  ) {}

  public close(): Promise<void> {
    return this.fnClose();
  }

  public async set(
    key: string,
    value: any,
    expires_sec: number,
  ): Promise<void> {
    await this.redis.set(key, JSON.stringify(value), 'EX', expires_sec);
  }

  public async tryGet(key: string): Promise<any | null> {
    const rawData = await this.redis.get(key);
    if (rawData == null) {
      return null;
    }

    const rv = JSON.parse(rawData);
    return rv;
  }
}

function createRedis(uri: string): IORedis.Redis {
  return new IORedis(uri, {
    lazyConnect: true,
    retryStrategy: attempt => {
      const baseMs = 100;
      const maxDelayMs = 10_000;

      const backoff = Math.min(maxDelayMs, Math.pow(2, attempt) * baseMs);

      return Math.round((backoff * (1 + Math.random())) / 2);
    },
  });
}
