import * as path from 'path';
import * as fs from 'fs/promises';
import {ISessionStorage, ITokenStorage} from './types';
import {Logger} from '@verdaccio/types';
import { TokenSet } from 'openid-client';

const TOKEN_FILE_EXT = '.token';
const SESSION_FILE_EXT = '.session';
const GC_TIMEOUT = 60 * 1_000;

export function NewFileStorage(
  logger: Logger,
  sessionStoragePath: string,
  tokenStoragePath: string,
): {ss: ISessionStorage; ts: ITokenStorage} {
  const gcPathSpec = [{path: sessionStoragePath, ext: [SESSION_FILE_EXT]}];

  if (sessionStoragePath === tokenStoragePath) {
    gcPathSpec[0].ext.push(TOKEN_FILE_EXT);
  } else {
    gcPathSpec.push({path: tokenStoragePath, ext: [TOKEN_FILE_EXT]});
  }

  setTimeout(() => gc(logger, gcPathSpec), GC_TIMEOUT);

  const stopByExt = (ext: string) => {
    for (let i = gcPathSpec.length - 1; i >= 0; --i) {
      const ps = gcPathSpec[i];
      ps.ext = ps.ext.filter(e => e != ext);
      if (ps.ext.length === 0) {
        gcPathSpec.length -= 1;
      }
    }

    return Promise.resolve();
  };

  return {
    ss: new FileSessionStorage(sessionStoragePath, () => {
      return stopByExt(SESSION_FILE_EXT);
    }),
    ts: new FileTokenStorage(tokenStoragePath, () => {
      return stopByExt(TOKEN_FILE_EXT);
    }),
  };
}

function btoa(s: string): string {
  return Buffer.from(s).toString('base64');
}

async function gc(logger: Logger, pathSpec: {path: string; ext: string[]}[]) {
  if (pathSpec.length === 0) {
    return;
  }

  try {
    for (const ps of pathSpec) {
      for (const f of await fs.readdir(ps.path, {encoding: 'utf-8'})) {
        const ff = path.join(ps.path, f);
        const stat = await fs.stat(ff);
        if (stat.isFile()) {
          const ext = path.extname(f);
          if (ps.ext.includes(ext)) {
            const fData = await fs.readFile(ff, {encoding: 'utf-8'});
            const expires_in = fData.slice(0, fData.indexOf('\n'));
            if (Date.now() > parseInt(expires_in, 10)) {
              await fs.rm(ff, {force: true, maxRetries: 3, retryDelay: 10});
            }
          }
        }
      }
    }
  } catch (err) {
    logger.warn({err}, 'file storage gc error: @{!err.message}\n@{err.stack}');
  } finally {
    setTimeout(() => gc(logger, pathSpec), GC_TIMEOUT);
  }
}

async function readFileEx(
  fName: string,
): Promise<{expires_in: number; objRaw: any}> {
  const fData = await fs.readFile(fName, {encoding: 'utf-8'});
  const sIdx = fData.indexOf('\n');
  const expires_in = fData.slice(0, sIdx);

  return {
    expires_in: parseInt(expires_in, 10),
    objRaw: fData.slice(sIdx + 1),
  };
}

class FileSessionStorage implements ISessionStorage {
  constructor(private path: string, private fnClose: () => Promise<void>) {}

  public async close(): Promise<void> {
    this.fnClose();
    return Promise.resolve();
  }

  public async set(
    key: string,
    value: TokenSet,
    expires_sec: number,
  ): Promise<void> {
    const fName = path.join(this.path, btoa(key) + SESSION_FILE_EXT);
    const fData = `${Date.now() + 100 * expires_sec}\n${JSON.stringify(
      value,
      null,
      2,
    )}`;
    await fs.writeFile(fName, fData, {encoding: 'utf-8'});
  }

  public async get(key: string): Promise<TokenSet | null> {
    try {
      const fName = path.join(this.path, btoa(key) + SESSION_FILE_EXT);
      const {expires_in, objRaw} = await readFileEx(fName);
      if (Date.now() > expires_in) {
        return null;
      }

      return JSON.parse(objRaw);
    } catch (_) {
      return null;
    }
  }
}

class FileTokenStorage implements ITokenStorage {
  constructor(private path: string, private fnClose: () => Promise<void>) {}

  public close(): Promise<void> {
    this.fnClose();
    return Promise.resolve();
  }

  public async set(
    key: string,
    value: string,
    expires_sec: number,
  ): Promise<void> {
    const fName = path.join(this.path, btoa(key) + TOKEN_FILE_EXT);
    const fData = `${Date.now() + 1000 * expires_sec}\n${value}`;
    await fs.writeFile(fName, fData, {encoding: 'utf-8'});
  }

  private async getSync(key: string): Promise<string | null> {
    try {
      const fName = path.join(this.path, btoa(key) + TOKEN_FILE_EXT);
      const {expires_in, objRaw} = await readFileEx(fName);
      if (Date.now() > expires_in) {
        return null;
      }

      return objRaw;
    } catch (_) {
      return null;
    }
  }

  public async get(key: string, timeout: number): Promise<string | null> {
    const rv = await this.getSync(key);
    if (rv != null) {
      return rv;
    }

    const eot = Date.now() + timeout * 1000;

    const tFn = (res: (value: any) => void) =>
      setTimeout(async () => {
        const rv = await this.getSync(key);
        if (rv != null) {
          return res(rv);
        }

        if (Date.now() < eot) {
          tFn(res);
        } else {
          res(null);
        }
      }, 100);

    const rvP = new Promise<string | null>((res, _) => {
      tFn(res);
    });

    return rvP;
  }
}
