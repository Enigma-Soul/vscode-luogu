import * as vscode from 'vscode';
import showLoginView from './ui';
import { randomUUID } from 'crypto';
import { checkCookie, genClientID, logout } from '@/utils/api';

class LuoguSession implements vscode.AuthenticationSession {
  readonly id = randomUUID();
  readonly accessToken: string;
  readonly account: vscode.AuthenticationSessionAccountInformation;
  readonly scopes = [];
  constructor(data: { uid: number; clientID: string; name: string }) {
    this.accessToken = data.clientID;
    this.account = { id: data.uid.toString(), label: data.name };
  }
}

export default class LuoguAuthProvider
  implements vscode.AuthenticationProvider, vscode.Disposable
{
  static readonly ProviderId = 'luogu-auth';
  static readonly SecretKey = 'luogu-auth';
  private readonly _sessionChangeEmitter =
    new vscode.EventEmitter<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent>();
  private readonly _disposables: vscode.Disposable[] = [];
  private cache: LuoguSession;
  private cacheLock: Promise<void>;
  private status: boolean = false;
  private disposed = false;
  // dispose 时 reject，让挂起的网络请求快速失败，避免 cacheLock 永久挂起
  private disposeReject!: (err: Error) => void;
  private readonly disposeGate = new Promise<never>((_, reject) => {
    this.disposeReject = (err: Error) => reject(err);
  });

  constructor(private readonly secretStorage: vscode.SecretStorage) {
    this.cache = {} as LuoguSession;
    this.cacheLock = this.initialize();
    this._disposables.push(this._sessionChangeEmitter);
    this._disposables.push(
      this.secretStorage.onDidChange(e => {
        if (e.key !== LuoguAuthProvider.SecretKey) return;
        this.cacheLock = this.cacheLock.then(
          () => this.reloadSession(),
          () => this.reloadSession()
        );
      })
    );
  }

  dispose() {
    if (this.disposed) return;
    this.disposed = true;
    this.disposeReject(new Error('LuoguAuthProvider disposed'));
    for (const disposable of this._disposables) disposable.dispose();
  }

  /** 与 dispose 竞速：dispose 后让挂起的网络请求快速失败 */
  private raceDispose<T>(promise: Promise<T>): Promise<T> {
    return Promise.race([promise, this.disposeGate]);
  }

  private async setContext(value: boolean) {
    if (this.disposed) return;
    await vscode.commands.executeCommand(
      'setContext',
      'luoguLoginStatus',
      value
    );
  }

  private fireChange(
    event: vscode.AuthenticationProviderAuthenticationSessionsChangeEvent
  ) {
    if (this.disposed) return;
    this._sessionChangeEmitter.fire(event);
  }

  private async initialize() {
    const stored = await this.secretStorage.get(LuoguAuthProvider.SecretKey);
    if (!stored) {
      await this.setAnonymousSession();
      return;
    }

    let session: LuoguSession;
    try {
      session = this.parseSession(stored);
    } catch {
      await this.secretStorage.delete(LuoguAuthProvider.SecretKey);
      await this.setAnonymousSession();
      return;
    }

    try {
      const valid = await this.raceDispose(
        checkCookie({
          uid: +session.account.id,
          clientID: session.accessToken
        })
      );
      if (!valid) {
        await this.secretStorage.delete(LuoguAuthProvider.SecretKey);
        await this.setAnonymousSession();
        return;
      }
    } catch {
      // dispose 后中止，不再保留 session
      if (this.disposed) return;
      // 网络错误：保留 session，下次请求再验证
    }

    this.cache = session;
    this.status = true;
    await this.setContext(true);
  }

  private async reloadSession() {
    if (this.disposed) return;
    const stored = await this.secretStorage.get(LuoguAuthProvider.SecretKey);
    if (stored) {
      let session: LuoguSession;
      try {
        session = this.parseSession(stored);
      } catch {
        await this.secretStorage.delete(LuoguAuthProvider.SecretKey);
        if (this.status) {
          const removed = this.cache;
          await this.setAnonymousSession();
          this.fireChange({ added: [], changed: [], removed: [removed] });
        }
        return;
      }

      const previous = this.status ? this.cache : undefined;
      this.cache = session;
      this.status = true;
      await this.setContext(true);
      this.fireChange({
        added: previous ? [] : [session],
        removed: [],
        changed: previous ? [session] : []
      });
      return;
    }

    if (!this.status) return;
    const removed = this.cache;
    await this.setAnonymousSession();
    this.fireChange({ added: [], changed: [], removed: [removed] });
  }

  private parseSession(value: string): LuoguSession {
    const parsed: unknown = JSON.parse(value);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      !('accessToken' in parsed) ||
      typeof parsed.accessToken !== 'string' ||
      !('account' in parsed) ||
      typeof parsed.account !== 'object' ||
      parsed.account === null ||
      !('id' in parsed.account) ||
      typeof parsed.account.id !== 'string' ||
      !('label' in parsed.account) ||
      typeof parsed.account.label !== 'string'
    ) {
      throw new Error('Invalid stored Luogu session');
    }
    return parsed as LuoguSession;
  }

  private async setAnonymousSession() {
    this.cache = new LuoguSession({
      uid: 0,
      clientID: await this.raceDispose(genClientID()),
      name: ''
    });
    this.status = false;
    await this.setContext(false);
  }

  get onDidChangeSessions(): vscode.Event<vscode.AuthenticationProviderAuthenticationSessionsChangeEvent> {
    return this._sessionChangeEmitter.event;
  }

  async createSession(): Promise<vscode.AuthenticationSession> {
    await this.cacheLock;
    if (this.status) return this.cache;
    const user = await showLoginView();
    if (user === null) throw new Error('Canceled');
    const session = new LuoguSession(user);
    await this.secretStorage.store(
      LuoguAuthProvider.SecretKey,
      JSON.stringify(session)
    );
    this.status = true;
    return session;
  }

  async getSessions(): Promise<readonly vscode.AuthenticationSession[]> {
    await this.cacheLock;
    return this.status ? [this.cache] : [];
  }

  async removeSession(sessionId: string) {
    await this.cacheLock;
    if (this.status) {
      if (this.cache.id === sessionId) {
        await this.raceDispose(
          this.cookie()
            .then(c => checkCookie(c))
            .then(x => (x ? logout() : undefined))
        ).catch(err => {
          vscode.window.showErrorMessage(
            `注销失败 ${err instanceof Error ? `：${err.message}` : `。`}\n将直接删除存储的 cookie 信息。`
          );
          console.error(err);
        });
        await this.secretStorage
          .delete(LuoguAuthProvider.SecretKey)
          .then(() => (this.status = false));
      }
    }
  }

  async user() {
    await this.cacheLock;
    return { uid: +this.cache.account.id, name: this.cache.account.label };
  }

  async cookie(): Promise<Cookie> {
    await this.cacheLock;
    return { uid: +this.cache.account.id, clientID: this.cache.accessToken };
  }
}
