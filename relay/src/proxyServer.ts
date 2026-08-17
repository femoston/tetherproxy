import {
  createServer,
  connect as netConnect,
  type Server,
  type Socket,
} from "node:net";
import { Store } from "./store.js";
import {
  parseProxyAuthorization,
  buildProxyAuthRequired,
  verifyPassword,
} from "./auth.js";
import { Mux } from "./mux.js";
import { ConnectionLimiter } from "./rateLimiter.js";
import {
  FrameType,
  encodeFrame,
  encodeJsonFrame,
} from "./frames.js";

/** The subset of a Tunnel the proxy server depends on. */
export interface TunnelLike {
  readonly mux: Mux;
  send(frame: Buffer): void;
  waitOpen(streamId: number): Promise<{ ok: boolean; reason?: string }>;
}

// Half-closed / silent client sockets (scanners that connect, never send a
// full request, and never complete the TCP close) would otherwise sit in
// FIN-WAIT-2 forever — "close"/"end" never fire, so their limiter slot is never
// released and `totalActive` leaks up to the global cap, after which the relay
// 429s everyone. An idle timeout destroys those sockets so the slot is freed.
// The timer is activity-based, so live CONNECT tunnels that keep streaming are
// never reaped.
const DEFAULT_IDLE_TIMEOUT_MS = 120_000;

export interface ProxyServerOptions {
  getLiveTunnel: () => TunnelLike | null;
  store: Store;
  allowedClientCidrs: string[];
  /** Optional connection limiter; one is created from defaults if omitted. */
  limiter?: ConnectionLimiter;
  /** Idle socket timeout (ms) before a stalled connection is reaped. */
  idleTimeoutMs?: number;
  /** Serve requests via the relay's own egress when the phone tunnel is down. */
  directFallback?: boolean;
  /** Domain suffixes eligible for direct fallback (empty = all targets). */
  directAllow?: string[];
}

/**
 * The dependencies a single proxy connection needs. Shared verbatim by the
 * plain `net.Server` and the TLS proxy listener (Task 11).
 */
export interface ProxyDeps {
  getLiveTunnel: () => TunnelLike | null;
  store: Store;
  allowedClientCidrs: string[];
  limiter: ConnectionLimiter;
  idleTimeoutMs: number;
  directFallback: boolean;
  directAllow: string[];
}

interface ParsedRequest {
  method: string;
  target: string;
  headers: Map<string, string>;
  raw: Buffer;
  headerEnd: number;
}

/**
 * Per-connection proxy handler shared by the plain `net.Server` and the TLS
 * proxy listener (Task 11). Applies the IP allowlist + connection limiter,
 * parses the request, validates Basic proxy-auth, finds the live tunnel, and
 * pipes bytes over a multiplexed stream. Always releases the limiter slot when
 * the socket closes.
 */
export function handleProxyConnection(sock: Socket, deps: ProxyDeps): void {
  sock.on("error", () => sock.destroy());

  // Reap stalled/half-closed sockets. setTimeout is activity-based (it resets on
  // read/write), so a live CONNECT tunnel that keeps streaming is never hit, but
  // a scanner that connects and goes silent — or a peer that never completes its
  // FIN — is destroyed, which fires "close" and releases its limiter slot.
  sock.setTimeout(deps.idleTimeoutMs);
  sock.on("timeout", () => sock.destroy());

  // IP allowlist (CIDR) check before anything else.
  const ip = (sock.remoteAddress ?? "").replace(/^::ffff:/, "");
  if (
    deps.allowedClientCidrs.length > 0 &&
    !ipAllowed(ip, deps.allowedClientCidrs)
  ) {
    sock.end(
      "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    return;
  }

  // Connection cap + rate limit. Reserve a slot and release it on close.
  const admit = deps.limiter.tryAcquire(ip);
  if (!admit.ok) {
    sock.end(
      "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    return;
  }
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    deps.limiter.release(ip);
  };
  // Release on "close" (always emitted) and also on "end" — once the peer has
  // sent FIN the connection is winding down, so freeing the slot a tick earlier
  // avoids a race where a follow-up connection from the same IP is rejected
  // before the prior socket's "close" handler runs. release() is idempotent.
  sock.on("close", release);
  sock.on("end", release);

  // Accumulate until we have a full header block.
  let buf = Buffer.alloc(0);
  const onData = (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    const end = buf.indexOf("\r\n\r\n");
    if (end === -1) {
      if (buf.length > 64 * 1024) {
        sock.off("data", onData);
        sock.end(
          "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n",
        );
      }
      return;
    }
    sock.off("data", onData);
    const parsed = parseRequest(buf, end);
    void handleRequest(sock, parsed, deps);
  };
  sock.on("data", onData);
}

/**
 * Raw TCP proxy server. Wraps a `net.Server` whose connections are handled by
 * the shared `handleProxyConnection`. The TLS listener in `index.ts` calls
 * `handleProxyConnection` directly with the same deps.
 */
export class ProxyServer {
  private readonly server: Server;
  readonly deps: ProxyDeps;

  constructor(opts: ProxyServerOptions) {
    this.deps = {
      getLiveTunnel: opts.getLiveTunnel,
      store: opts.store,
      allowedClientCidrs: opts.allowedClientCidrs,
      limiter: opts.limiter ?? new ConnectionLimiter(),
      idleTimeoutMs: opts.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
      directFallback: opts.directFallback ?? false,
      directAllow: opts.directAllow ?? [],
    };
    this.server = createServer((sock) => handleProxyConnection(sock, this.deps));
  }

  /** Start listening; resolves with the bound port. */
  listen(port: number, host = "0.0.0.0"): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.once("error", reject);
      this.server.listen(port, host, () => {
        const addr = this.server.address();
        resolve(typeof addr === "object" && addr ? addr.port : port);
      });
    });
  }

  /** Stop the server. */
  close(): void {
    this.server.close();
  }
}

async function handleRequest(
  sock: Socket,
  req: ParsedRequest,
  deps: ProxyDeps,
): Promise<void> {
  // 1. Validate proxy auth.
  const creds = parseProxyAuthorization(req.headers.get("proxy-authorization"));
  if (!creds) {
    sock.end(buildProxyAuthRequired());
    return;
  }
  const rec = deps.store.findByUsername(creds.username);
  if (!rec || !(await verifyPassword(creds.password, rec.bcryptPassword))) {
    sock.end(buildProxyAuthRequired());
    return;
  }

  // 2. Find a live phone tunnel. When it's down (the phone egress drops
  // silently and often — see 2026-07/08 flagship outages) optionally degrade
  // to the relay's own egress instead of 503ing every client.
  const tunnel = deps.getLiveTunnel();
  if (!tunnel) {
    if (directEligible(deps, req)) {
      console.log(
        `[relay] proxy: no live tunnel — direct-egress fallback for ${req.target}`,
      );
      handleDirect(sock, req);
      return;
    }
    sock.end(
      "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    return;
  }

  if (req.method === "CONNECT") {
    await handleConnect(sock, req, tunnel, deps);
  } else {
    await handleAbsoluteHttp(sock, req, tunnel, deps);
  }
}

/** Target host of a proxy request (CONNECT host:port or absolute-form URI). */
function requestHost(req: ParsedRequest): string | null {
  if (req.method === "CONNECT") {
    return parseHostPort(req.target, 443)?.host ?? null;
  }
  const m = /^https?:\/\/([^/]+)(\/.*)?$/i.exec(req.target);
  return m ? (parseHostPort(m[1], 80)?.host ?? null) : null;
}

function directEligible(deps: ProxyDeps, req: ParsedRequest): boolean {
  if (!deps.directFallback) return false;
  const host = requestHost(req);
  if (!host) return false;
  if (deps.directAllow.length === 0) return true;
  const h = host.toLowerCase();
  return deps.directAllow.some((s) => h === s || h.endsWith("." + s));
}

/** Serve a proxy request via the relay's own egress (no phone tunnel). */
function handleDirect(sock: Socket, req: ParsedRequest): void {
  if (req.method === "CONNECT") {
    const target = parseHostPort(req.target, 443);
    if (!target) {
      sock.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return;
    }
    const upstream = netConnect(target.port, target.host, () => {
      sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      // Bytes the client optimistically sent after the CONNECT header.
      const early = req.raw.subarray(req.headerEnd + 4);
      if (early.length > 0) upstream.write(early);
      sock.pipe(upstream);
      upstream.pipe(sock);
    });
    wireDirectPair(sock, upstream);
    return;
  }

  const m = /^https?:\/\/([^/]+)(\/.*)?$/i.exec(req.target);
  const target = m ? parseHostPort(m[1], 80) : null;
  if (!target) {
    sock.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return;
  }
  const path = (m && m[2]) || "/";
  const upstream = netConnect(target.port, target.host, () => {
    upstream.write(rebuildOriginForm(req, path));
    sock.pipe(upstream);
    upstream.pipe(sock);
  });
  wireDirectPair(sock, upstream);
}

/** Tie the lifetimes of the client socket and the direct upstream together. */
function wireDirectPair(sock: Socket, upstream: Socket): void {
  upstream.on("error", () => {
    if (!sock.writableEnded) {
      sock.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    }
    upstream.destroy();
  });
  upstream.on("close", () => sock.destroy());
  sock.on("close", () => upstream.destroy());
  sock.on("error", () => upstream.destroy());
}

async function handleConnect(
  sock: Socket,
  req: ParsedRequest,
  tunnel: TunnelLike,
  deps: ProxyDeps,
): Promise<void> {
  const target = parseHostPort(req.target, 443);
  if (!target) {
    sock.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return;
  }
  const streamId = tunnel.mux.allocate(sock);
  const waiter = tunnel.waitOpen(streamId);
  tunnel.send(
    encodeJsonFrame(FrameType.OPEN, streamId, {
      host: target.host,
      port: target.port,
    }),
  );
  const result = await waiter;
  if (!result.ok) {
    tunnel.mux.delete(streamId);
    // The tunnel exists but couldn't open the stream (phone flapping /
    // half-dead). Same degraded path as no-tunnel: try direct egress.
    if (directEligible(deps, req)) {
      console.log(
        `[relay] proxy: tunnel OPEN failed — direct-egress fallback for ${req.target}`,
      );
      handleDirect(sock, req);
      return;
    }
    sock.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    return;
  }
  sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  pipeStream(sock, tunnel, streamId, Buffer.alloc(0));
}

async function handleAbsoluteHttp(
  sock: Socket,
  req: ParsedRequest,
  tunnel: TunnelLike,
  deps: ProxyDeps,
): Promise<void> {
  // Absolute-form request target: METHOD http://host[:port]/path HTTP/1.1
  const m = /^https?:\/\/([^/]+)(\/.*)?$/i.exec(req.target);
  if (!m) {
    sock.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return;
  }
  const target = parseHostPort(m[1], 80);
  if (!target) {
    sock.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
    return;
  }
  const path = m[2] || "/";

  const streamId = tunnel.mux.allocate(sock);
  const waiter = tunnel.waitOpen(streamId);
  tunnel.send(
    encodeJsonFrame(FrameType.OPEN, streamId, {
      host: target.host,
      port: target.port,
    }),
  );
  const result = await waiter;
  if (!result.ok) {
    tunnel.mux.delete(streamId);
    if (directEligible(deps, req)) {
      console.log(
        `[relay] proxy: tunnel OPEN failed — direct-egress fallback for ${req.target}`,
      );
      handleDirect(sock, req);
      return;
    }
    sock.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    return;
  }

  // Rebuild the request in origin-form (strip the absolute URI, drop hop
  // headers) and forward it as the first DATA chunk, then pipe the rest.
  const rebuilt = rebuildOriginForm(req, path);
  pipeStream(sock, tunnel, streamId, rebuilt);
}

/**
 * Bidirectional pipe: client socket <-> phone tunnel stream.
 * `initial` is bytes already read from the client to forward immediately.
 */
function pipeStream(
  sock: Socket,
  tunnel: TunnelLike,
  streamId: number,
  initial: Buffer,
): void {
  if (initial.length > 0) {
    tunnel.send(encodeFrame(FrameType.DATA, streamId, initial));
  }
  sock.on("data", (chunk: Buffer) => {
    tunnel.send(encodeFrame(FrameType.DATA, streamId, chunk));
  });
  const teardown = () => {
    if (tunnel.mux.get(streamId)) {
      tunnel.mux.delete(streamId);
      tunnel.send(encodeFrame(FrameType.CLOSE, streamId));
    }
  };
  sock.on("close", teardown);
  sock.on("end", teardown);
  sock.on("error", () => {
    teardown();
    sock.destroy();
  });
}

function parseRequest(buf: Buffer, headerEnd: number): ParsedRequest {
  const headText = buf.subarray(0, headerEnd).toString("utf8");
  const lines = headText.split("\r\n");
  const [method, target] = lines[0].split(" ");
  const headers = new Map<string, string>();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const c = line.indexOf(":");
    if (c === -1) continue;
    const k = line.slice(0, c).trim().toLowerCase();
    const v = line.slice(c + 1).trim();
    headers.set(k, v);
  }
  return { method, target, headers, raw: buf, headerEnd };
}

function parseHostPort(
  s: string,
  defaultPort: number,
): { host: string; port: number } | null {
  const idx = s.lastIndexOf(":");
  if (idx === -1) return { host: s, port: defaultPort };
  const host = s.slice(0, idx);
  const port = Number(s.slice(idx + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (host.length === 0) return null;
  return { host, port };
}

const HOP_HEADERS = new Set([
  "proxy-authorization",
  "proxy-connection",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

function rebuildOriginForm(req: ParsedRequest, path: string): Buffer {
  const reqLine = `${req.method} ${path} HTTP/1.1\r\n`;
  let head = reqLine;
  for (const [k, v] of req.headers) {
    if (HOP_HEADERS.has(k)) continue;
    head += `${capitalizeHeader(k)}: ${v}\r\n`;
  }
  head += "Connection: close\r\n\r\n";
  // Include any body bytes that arrived after the header block.
  const body = req.raw.subarray(req.headerEnd + 4);
  return Buffer.concat([Buffer.from(head, "utf8"), body]);
}

function capitalizeHeader(name: string): string {
  return name
    .split("-")
    .map((p) => (p.length ? p[0].toUpperCase() + p.slice(1) : p))
    .join("-");
}

/** Check whether an IP is within any of the given CIDRs (IPv4 only, v1). */
export function ipAllowed(ip: string, cidrs: string[]): boolean {
  const addr = ip.replace(/^::ffff:/, "");
  const ipNum = ipv4ToInt(addr);
  if (ipNum === null) return false;
  for (const cidr of cidrs) {
    const [net, bitsRaw] = cidr.split("/");
    const bits = Number(bitsRaw);
    const netNum = ipv4ToInt(net);
    if (netNum === null || !Number.isInteger(bits)) continue;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((ipNum & mask) === (netNum & mask)) return true;
  }
  return false;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}
