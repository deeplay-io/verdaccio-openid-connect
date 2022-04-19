export interface ISessionStorage {
  close(): Promise<void>;
  set(key: string, value: any, expires_sec: number): Promise<void>;
  tryGet(key: string): Promise<any | null>;
}

export interface ITokenStorage {
  close(): Promise<void>;
  set(key: string, value: any, expires_sec: number): Promise<void>;
  tryGet(key: string, timeout: number): Promise<any | null>;
}
