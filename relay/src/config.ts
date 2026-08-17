export interface RateLimitConfig {
  maxTotal: number;
  maxPerIp: number;
  maxNewPerMin: number;
  windowMs: number;
}

export interface Config {
  pairingToken: string;
  proxyPort: number;
  proxyTlsPort: number | undefined;
  tunnelPort: number;
  allowedClientCidrs: string[];
  dataDir: string;
  certDir: string;
  tlsCertPath: string;
  tlsKeyPath: string;
  rateLimit: RateLimitConfig;
  /** Public IP/host of the relay; used only to print the app pairing string. */
  publicHost: string | undefined;
  /**
   * When the phone tunnel is down, serve proxy requests via the relay's own
   * egress instead of failing with 503/502. Off by default: the phone's
   * residential IP is the product; direct egress is a degraded emergency mode.
   */
  directFallback: boolean;
  /**
   * Domain suffixes allowed for direct-egress fallback (exact host or any
   * subdomain). Empty list = allow all targets, same as the phone tunnel.
   */
  directAllow: string[];
}

function parsePort(raw: string | undefined, name: string, def: number): number {
  if (raw === undefined || raw === "") return def;
  const n = Number(raw);
  // 0 is permitted as the OS-assigned ephemeral-port sentinel (used by tests
  // and for "bind any free port"); other out-of-range values are rejected.
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`${name} must be an integer 0-65535, got "${raw}"`);
  }
  return n;
}

function parsePositiveInt(
  raw: string | undefined,
  name: string,
  def: number,
): number {
  if (raw === undefined || raw === "") return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error(`${name} must be a positive integer, got "${raw}"`);
  }
  return n;
}

function parseOptionalPort(
  raw: string | undefined,
  name: string,
): number | undefined {
  if (raw === undefined || raw === "") return undefined;
  const n = Number(raw);
  // 0 is permitted as the OS-assigned ephemeral-port sentinel; an explicit "0"
  // still enables the optional listener (unset/"" is what disables it).
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`${name} must be an integer 0-65535, got "${raw}"`);
  }
  return n;
}

/** Parse environment variables (defaults to process.env) into a Config. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const pairingToken = env.PAIRING_TOKEN;
  if (!pairingToken || pairingToken.length === 0) {
    throw new Error("PAIRING_TOKEN is required");
  }
  const dataDir = env.DATA_DIR || "/data";
  const certDir = env.CERT_DIR || "/certs";
  const allowedClientCidrs = (env.ALLOWED_CLIENT_CIDRS || "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const directFallback =
    env.DIRECT_FALLBACK === "1" || env.DIRECT_FALLBACK === "true";
  // "*" opts into allow-all; unset keeps the Instagram-only default so a
  // leaked credential can't turn the relay into a general open proxy.
  const directAllowRaw = env.DIRECT_ALLOW ?? "";
  const directAllow =
    directAllowRaw.trim() === "*"
      ? []
      : directAllowRaw
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter((s) => s.length > 0);
  if (directAllowRaw.trim() === "" ) {
    directAllow.push("instagram.com", "cdninstagram.com", "fbcdn.net");
  }

  return {
    pairingToken,
    proxyPort: parsePort(env.PROXY_PORT, "PROXY_PORT", 8080),
    proxyTlsPort: parseOptionalPort(env.PROXY_TLS_PORT, "PROXY_TLS_PORT"),
    tunnelPort: parsePort(env.TUNNEL_PORT, "TUNNEL_PORT", 8443),
    allowedClientCidrs,
    dataDir,
    certDir,
    tlsCertPath: env.TLS_CERT_PATH || `${certDir}/tunnel-cert.pem`,
    tlsKeyPath: env.TLS_KEY_PATH || `${certDir}/tunnel-key.pem`,
    publicHost: env.RELAY_PUBLIC_HOST || undefined,
    directFallback,
    directAllow,
    rateLimit: {
      maxTotal: parsePositiveInt(
        env.RATE_LIMIT_MAX_TOTAL,
        "RATE_LIMIT_MAX_TOTAL",
        512,
      ),
      maxPerIp: parsePositiveInt(
        env.RATE_LIMIT_MAX_PER_IP,
        "RATE_LIMIT_MAX_PER_IP",
        64,
      ),
      maxNewPerMin: parsePositiveInt(
        env.RATE_LIMIT_MAX_NEW_PER_MIN,
        "RATE_LIMIT_MAX_NEW_PER_MIN",
        120,
      ),
      windowMs: parsePositiveInt(
        env.RATE_LIMIT_WINDOW_MS,
        "RATE_LIMIT_WINDOW_MS",
        60000,
      ),
    },
  };
}
