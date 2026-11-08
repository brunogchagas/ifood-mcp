import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { RestartSafeClientsStore } from "../build/http/store.js";

const metadata = {
  redirect_uris: ["https://example.com/oauth/callback"],
  token_endpoint_auth_method: "client_secret_post",
  client_secret: "test-only-client-secret",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  client_name: "Restart test",
};

test("registration survives a new store with the same key", async () => {
  const key = randomBytes(32);
  const original = await new RestartSafeClientsStore(key).registerClient(metadata);
  assert.deepEqual(new RestartSafeClientsStore(key).getClient(original.client_id), original);
  assert.ok(!Buffer.from(original.client_id.slice(9), "base64url").includes(Buffer.from(metadata.client_secret)));
});

test("modified IDs, unknown IDs and a different server key are rejected", async () => {
  const key = randomBytes(32);
  const store = new RestartSafeClientsStore(key);
  const { client_id } = await store.registerClient(metadata);
  const pos = 40;
  const tampered = client_id.slice(0, pos) + (client_id[pos] === "A" ? "B" : "A") + client_id.slice(pos + 1);
  for (const id of [tampered, "ifood_old_missing_client", "ifood_v1_", client_id + "=", "x".repeat(20000)]) {
    assert.equal(store.getClient(id), undefined);
  }
  assert.equal(new RestartSafeClientsStore(randomBytes(32)).getClient(client_id), undefined);
  assert.throws(() => new RestartSafeClientsStore(Buffer.alloc(3)));
});

test("public clients have distinct registrations and no client secret", async () => {
  const store = new RestartSafeClientsStore(randomBytes(32));
  const input = { redirect_uris: metadata.redirect_uris, token_endpoint_auth_method: "none" };
  const a = await store.registerClient(input);
  const b = await store.registerClient(input);
  assert.notEqual(a.client_id, b.client_id);
  assert.equal(store.getClient(a.client_id).client_secret, undefined);
});

test("HTTP registration still authorizes after a complete server restart", { timeout: 20000 }, async () => {
  const port = 32191;
  const base = `http://localhost:${port}`;
  const secret = randomBytes(32).toString("hex");
  let child;
  const start = async () => {
    child = spawn(process.execPath, ["build/http-server.js"], {
      env: { ...process.env, PORT: String(port), PUBLIC_URL: base, MCP_JWT_SECRET: secret },
      stdio: ["ignore", "pipe", "pipe"],
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("Server did not become ready")), 5000);
      child.once("exit", () => { clearTimeout(timer); reject(new Error("Server exited before ready")); });
      child.stdout.on("data", chunk => {
        if (chunk.toString().includes("remote listening")) { clearTimeout(timer); resolve(); }
      });
    });
  };
  const stop = async () => {
    if (child && child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited;
    }
  };
  try {
    await start();
    const response = await fetch(`${base}/register`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...metadata, client_secret: undefined }),
    });
    assert.equal(response.status, 201);
    const registered = await response.json();
    assert.ok(registered.client_secret);
    await stop();
    await start();
    const params = new URLSearchParams({
      client_id: registered.client_id, redirect_uri: metadata.redirect_uris[0],
      response_type: "code", code_challenge_method: "S256",
      code_challenge: createHash("sha256").update(randomBytes(32)).digest("base64url"),
      scope: "mcp:tools", resource: `${base}/mcp`,
    });
    const authorize = await fetch(`${base}/authorize?${params}`, { redirect: "manual" });
    assert.equal(authorize.status, 302);
    assert.equal(new URL(authorize.headers.get("location")).pathname, "/login");
    params.set("redirect_uri", "https://attacker.example/callback");
    const wrongRedirect = await fetch(`${base}/authorize?${params}`, { redirect: "manual" });
    assert.equal(wrongRedirect.status, 400);
  } finally {
    await stop();
  }
});
