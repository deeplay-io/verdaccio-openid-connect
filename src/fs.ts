import * as path from 'path';
import * as fs from 'fs/promises';
import {ISessionStorage, ITokenStorage} from './types';

export function NewFileStorage(
  sessionStoragePath: string,
  tokenStoragePath: string,
): {ss: ISessionStorage; ts: ITokenStorage} {
  setTimeout(() => {
    gc([sessionStoragePath, tokenStoragePath]);
  }, 60 * 1_000);

  return {
    ss: new FileSessionStorage(sessionStoragePath),
    ts: new FileTokenStorage(tokenStoragePath),
  };
}

function btoa(s: string): string {
  return Buffer.from(s).toString('base64');
}

async function gc(paths: string[]) {
  try {
    for (const p of paths) {
      for (const f of await fs.readdir(p, {encoding: 'utf-8'})) {
        const ff = path.join(p, f);
        const stat = await fs.stat(ff);
        if (stat.isFile()) {
          const ext = path.extname(f);
          if (ext == '.session' || ext == '.token') {
            const fData = await fs.readFile(ff, {encoding: 'utf-8'});
            const expires_in = fData.slice(0, fData.indexOf('\n'));
            if (Date.now() > parseInt(expires_in, 10)) {
              await fs.rm(ff, {force: true, maxRetries: 3, retryDelay: 10});
            }
          }
        }
      }
    }
  } catch (e) {
    console.warn('file storage gc error', e);
  } finally {
    setTimeout(() => {
      gc(paths);
    }, 60 * 1_000);
  }
}

async function readFileEx(fName: string): Promise<{expires_in: number, objRaw: any}>{
  const fData = await fs.readFile(fName, {encoding: 'utf-8'});
  const sIdx = fData.indexOf('\n');
  const expires_in = fData.slice(0, sIdx);

  return {
    expires_in: parseInt(expires_in, 10),
    objRaw: fData.slice(sIdx+1)
  }
}

class FileSessionStorage implements ISessionStorage {
  constructor(private path: string) {}

  public async close(): Promise<void> {
    return Promise.resolve();
  }

  public async set(
    key: string,
    value: any,
    expires_sec: number,
  ): Promise<void> {
    const fName = path.join(this.path, btoa(key) + '.session');
    const fData = `${Date.now() + 100 * expires_sec}\n${JSON.stringify(
      value,
      null,
      2,
    )}`;
    await fs.writeFile(fName, fData, {encoding: 'utf-8'});
  }

  public async tryGet(key: string): Promise<any> {
    try {
      const fName = path.join(this.path, btoa(key) + '.session');
      const {expires_in, objRaw} = await readFileEx(fName)
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
  constructor(private path: string) {}

  public close(): Promise<void> {
    return Promise.resolve();
  }

  public async set(
    key: string,
    value: any,
    expires_sec: number,
  ): Promise<void> {
    const fName = path.join(this.path, btoa(key) + '.token');
    const fData = `${Date.now() + 1000 * expires_sec}\n${JSON.stringify(
      value,
      null,
      2,
    )}`;
    await fs.writeFile(fName, fData, {encoding: 'utf-8'});
  }

  private async tryGetSync(key: string) {
    try {
      const fName = path.join(this.path, btoa(key) + '.token');
      const {expires_in, objRaw} = await readFileEx(fName)
      if (Date.now() > expires_in) {
        return null;
      }

      return JSON.parse(objRaw);
    } catch (_) {
      return null;
    }
  }

  public async tryGet(key: string, timeout: number): Promise<any> {
    const rv = await this.tryGetSync(key);
    if (rv != null) {
      return rv;
    }

    const eot = Date.now() + timeout * 1000;

    const tFn = (res: (value: any) => void) =>
      setTimeout(async () => {
        const rv = await this.tryGetSync(key);
        if (rv != null) {
          return res(rv);
        }

        if (Date.now() < eot) {
          tFn(res);
        } else {
          res(null);
        }
      }, 100);

    const rvP = new Promise((res, _) => {
      tFn(res);
    });

    return rvP;
  }
}
