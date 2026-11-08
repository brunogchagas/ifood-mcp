/**
 * Restart-safe OAuth client registrations and in-memory authorization/session
 * stores. User sessions remain single-process and require login after restart.
 */

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from "crypto";
import { OAuthClientInformationFullSchema } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";

function randomId(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}

/* ----------------------------- DCR clients -------------------------------- */

export class RestartSafeClientsStore implements OAuthRegisteredClientsStore {
  private readonly key: Buffer;
  private readonly prefix = "ifood_v1_";

  constructor(secret: Uint8Array) {
    if (secret.length < 32) throw new Error("OAuth client key must be at least 32 bytes");
    this.key = Buffer.from(hkdfSync("sha256", secret,
      "ifood-mcp", "oauth-client-registration-v1", 32));
  }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    // A sealed registration survives process restarts without an ephemeral
    // filesystem or database. Authentication secrets remain encrypted.
    if (!clientId.startsWith(this.prefix) || clientId.length > 16384) return undefined;
    try {
      const encoded = clientId.slice(this.prefix.length);
      const sealed = Buffer.from(encoded, "base64url");
      if (sealed.length < 29 || sealed.toString("base64url") !== encoded) return undefined;
      const decipher = createDecipheriv("aes-256-gcm", this.key, sealed.subarray(0, 12));
      decipher.setAAD(Buffer.from(this.prefix));
      decipher.setAuthTag(sealed.subarray(12, 28));
      const json = Buffer.concat([decipher.update(sealed.subarray(28)), decipher.final()]);
      return OAuthClientInformationFullSchema.parse({ ...JSON.parse(json.toString()), client_id: clientId });
    } catch {
      return undefined;
    }
  }

  async registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">
  ): Promise<OAuthClientInformationFull> {
    // The SDK may pass its own generated client_id; never embed that value.
    const { client_id: _ignored, ...metadata } = client as OAuthClientInformationFull;
    const record = {
      ...metadata,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(Buffer.from(this.prefix));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(record)), cipher.final()]);
    const clientId = this.prefix + Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");
    if (clientId.length > 16384) throw new Error("OAuth client metadata is too large");
    return { ...record, client_id: clientId };
  }
}

/* ----------------------- Pending authorization flows ---------------------- */

export type PendingAuthFlow = {
  flowId: string;
  clientId: string;
  redirectUri: string;
  state?: string;
  scopes: string[];
  codeChallenge: string;
  resource?: string;
  createdAt: number;
  expiresAt: number;
  /** Per-flow device + session UUIDs. Generated at flow creation; bound to the eventual iFood tokens. */
  deviceId: string;
  sessionId: string;
  /** Step 2 → 3 link: opaque key returned by /authorization-codes. */
  otpKey?: string;
  /** Identifier the user submitted (email or "+55..."). For UX echo-back. */
  identifier?: string;
  /** "EMAIL" | "SMS" | "WHATSAPP" — channel chosen for OTP delivery. */
  otpChannel?: string;
  /** Resolved email — as typed (email login) or supplied via the email-challenge page (phone login). */
  resolvedEmail?: string;
  /** Opaque token from step 3, reused in steps 4 and 5. */
  otpToken?: string;
  /** Masked email returned by step 4 — shown as a hint when prompting for the real email. */
  maskedEmail?: string;
};

export class PendingAuthStore {
  private flows = new Map<string, PendingAuthFlow>();

  create(
    partial: Omit<PendingAuthFlow, "flowId" | "createdAt" | "expiresAt" | "deviceId" | "sessionId"> &
      Partial<Pick<PendingAuthFlow, "deviceId" | "sessionId">>,
    ttlSec = 600
  ): PendingAuthFlow {
    const now = Math.floor(Date.now() / 1000);
    const flow: PendingAuthFlow = {
      ...partial,
      flowId: randomId(16),
      createdAt: now,
      expiresAt: now + ttlSec,
      deviceId: partial.deviceId ?? randomUUID(),
      sessionId: partial.sessionId ?? randomUUID(),
    };
    this.flows.set(flow.flowId, flow);
    return flow;
  }

  get(flowId: string): PendingAuthFlow | undefined {
    const f = this.flows.get(flowId);
    if (!f) return undefined;
    if (f.expiresAt < Math.floor(Date.now() / 1000)) {
      this.flows.delete(flowId);
      return undefined;
    }
    return f;
  }

  update(flowId: string, patch: Partial<PendingAuthFlow>): void {
    const f = this.flows.get(flowId);
    if (!f) return;
    this.flows.set(flowId, { ...f, ...patch });
  }

  delete(flowId: string): void {
    this.flows.delete(flowId);
  }
}

/* ---------------------- Authorization codes (short-lived) ----------------- */

export type AuthCode = {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  userSub: string;
  expiresAt: number;
};

export class AuthCodeStore {
  private codes = new Map<string, AuthCode>();

  create(partial: Omit<AuthCode, "code" | "expiresAt">, ttlSec = 60): AuthCode {
    const ac: AuthCode = {
      ...partial,
      code: randomId(24),
      expiresAt: Math.floor(Date.now() / 1000) + ttlSec,
    };
    this.codes.set(ac.code, ac);
    return ac;
  }

  peek(code: string): AuthCode | undefined {
    const ac = this.codes.get(code);
    if (!ac) return undefined;
    if (ac.expiresAt < Math.floor(Date.now() / 1000)) {
      this.codes.delete(code);
      return undefined;
    }
    return ac;
  }

  take(code: string): AuthCode | undefined {
    const ac = this.peek(code);
    if (!ac) return undefined;
    this.codes.delete(code);
    return ac;
  }
}

/* ------------------------- MCP refresh tokens ----------------------------- */

export type RefreshRecord = {
  refreshToken: string;
  clientId: string;
  userSub: string;
  resource?: string;
  scopes: string[];
  expiresAt: number;
};

export class RefreshTokenStore {
  private tokens = new Map<string, RefreshRecord>();

  create(
    partial: Omit<RefreshRecord, "refreshToken" | "expiresAt">,
    ttlSec = 60 * 60 * 24 * 30
  ): RefreshRecord {
    const r: RefreshRecord = {
      ...partial,
      refreshToken: randomId(32),
      expiresAt: Math.floor(Date.now() / 1000) + ttlSec,
    };
    this.tokens.set(r.refreshToken, r);
    return r;
  }

  take(token: string): RefreshRecord | undefined {
    const r = this.tokens.get(token);
    if (!r) return undefined;
    this.tokens.delete(token); // single-use rotation
    if (r.expiresAt < Math.floor(Date.now() / 1000)) return undefined;
    return r;
  }
}

/* ------------------- Per-user iFood API tokens (downstream) --------------- */

export type iFoodTokenPair = {
  accessToken: string;
  refreshToken: string;
  accountId: string;
  deviceId: string;
  sessionId: string;
};

export class UserTokenStore {
  private byId = new Map<string, iFoodTokenPair>();

  set(userSub: string, pair: iFoodTokenPair): void {
    this.byId.set(userSub, pair);
  }

  get(userSub: string): iFoodTokenPair | undefined {
    return this.byId.get(userSub);
  }

  has(userSub: string): boolean {
    return this.byId.has(userSub);
  }

  allIds(): string[] {
    return Array.from(this.byId.keys());
  }
}
