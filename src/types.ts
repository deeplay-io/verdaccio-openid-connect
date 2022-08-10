import {TokenSet} from 'openid-client';

export interface ISessionStorage {
  close(): Promise<void>;
  set(key: string, value: TokenSet, expires_sec: number): Promise<void>;
  get(key: string): Promise<TokenSet | null>;
}

export interface ITokenStorage {
  close(): Promise<void>;
  set(key: string, value: string, expires_sec: number): Promise<void>;
  get(key: string, timeout: number): Promise<string | null>;
}
