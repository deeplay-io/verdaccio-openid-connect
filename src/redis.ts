import IORedis = require('ioredis');

export function createRedis(uri: string): IORedis.Redis {
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
