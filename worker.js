// Horus Terminal Relay (secure version)
// - Token authentication (RELAY_TOKEN secret)
// - One Durable Object per session (reliable routing between phone and browsers)
// - WebSocket Hibernation API (cheap idle connections)
//
// Host (phone):    wss://<worker>/host?id=SESSION_ID&token=TOKEN
// Client (browser): wss://<worker>/client?id=SESSION_ID&token=TOKEN
//
// Browsers can also send the token as a WebSocket subprotocol to keep it out of the URL:
//   new WebSocket("wss://<worker>/client?id=SESSION_ID", ["token." + TOKEN])
//
// Required secret : RELAY_TOKEN          (min 32 random chars)
// Optional var    : ALLOWED_ORIGINS      (comma separated, e.g. "https://my-site.pages.dev")

import { DurableObject } from "cloudflare:workers";

const SESSION_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const MAX_CLIENTS_PER_SESSION = 5;
const MAX_MESSAGE_SIZE = 1024 * 1024; // 1 MB

// ---------------------------------------------------------------------------
// Front Worker: validates the request, then forwards it to the session's DO
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") {
      return handleUpgrade(request, env, url);
    }

    if (url.pathname === "/status") {
      return json({ status: "ok", message: "Horus Relay is running" });
    }

    if (url.pathname === "/") {
      return new Response(landingPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (url.pathname === "/host" || url.pathname === "/client") {
      return new Response("Expected a WebSocket connection", { status: 426 });
    }

    return new Response("Not Found", { status: 404 });
  },
};

async function handleUpgrade(request, env, url) {
  if (url.pathname !== "/host" && url.pathname !== "/client") {
    return new Response("Invalid path. Use /host or /client", { status: 404 });
  }

  if (!env.RELAY_TOKEN || env.RELAY_TOKEN.length < 16) {
    return new Response("Server is not configured (RELAY_TOKEN missing or too short)", { status: 500 });
  }

  const sessionId = url.searchParams.get("id") || "";
  if (!SESSION_ID_RE.test(sessionId)) {
    return new Response("Invalid session id (8-64 chars: letters, digits, _ and -)", { status: 400 });
  }

  const token = extractToken(request, url);
  if (!(await safeEqual(token, env.RELAY_TOKEN))) {
    return new Response("Unauthorized", { status: 401 });
  }

  // Optional: only allow browsers from specific origins to connect as clients
  if (url.pathname === "/client" && env.ALLOWED_ORIGINS) {
    const origin = request.headers.get("Origin");
    const allowed = env.ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean);
    if (origin && !allowed.includes(origin)) {
      return new Response("Origin not allowed", { status: 403 });
    }
  }

  const stub = env.RELAY.get(env.RELAY.idFromName(sessionId));
  return stub.fetch(request);
}

// Token from ?token=... or from the "token.<value>" WebSocket subprotocol
function extractToken(request, url) {
  const fromQuery = url.searchParams.get("token");
  if (fromQuery) return fromQuery;
  const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "")
    .split(",")
    .map((s) => s.trim());
  const p = protocols.find((x) => x.startsWith("token."));
  return p ? p.slice(6) : "";
}

// Constant-time comparison (hash both sides so lengths always match)
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(String(a))),
    crypto.subtle.digest("SHA-256", enc.encode(String(b))),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ---------------------------------------------------------------------------
// Durable Object: one instance per session id
// Tags: "host" (the phone) and "client" (browsers)
// ---------------------------------------------------------------------------
export class RelayRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // Keep-alive without waking the object: client sends "ping", gets "pong"
    this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  async fetch(request) {
    const url = new URL(request.url);
    const role = url.pathname === "/host" ? "host" : "client";

    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("Expected a WebSocket connection", { status: 426 });
    }

    if (role === "client" && this.open("client").length >= MAX_CLIENTS_PER_SESSION) {
      return new Response("Too many clients for this session", { status: 429 });
    }

    // Only one host per session: a new host replaces the old one
    if (role === "host") {
      for (const old of this.open("host")) {
        try { old.close(4000, "Replaced by a new host"); } catch {}
      }
    }

    const pair = new WebSocketPair();
    const [clientSide, serverSide] = Object.values(pair);
    this.ctx.acceptWebSocket(serverSide, [role]);

    // If the browser used the "token.<value>" subprotocol, the server must echo one back
    const headers = new Headers();
    const protocols = (request.headers.get("Sec-WebSocket-Protocol") || "")
      .split(",")
      .map((s) => s.trim());
    const tokenProtocol = protocols.find((x) => x.startsWith("token."));
    if (tokenProtocol) headers.set("Sec-WebSocket-Protocol", tokenProtocol);

    if (role === "host") {
      this.broadcast("client", JSON.stringify({ type: "host_connected" }));
    } else if (this.open("host").length > 0) {
      serverSide.send(JSON.stringify({ type: "host_connected" }));
    } else {
      serverSide.send(JSON.stringify({ type: "error", message: "Host not connected. Waiting..." }));
    }

    return new Response(null, { status: 101, webSocket: clientSide, headers });
  }

  async webSocketMessage(ws, message) {
    const size = typeof message === "string" ? message.length : message.byteLength;
    if (size > MAX_MESSAGE_SIZE) {
      try { ws.close(1009, "Message too big"); } catch {}
      return;
    }

    const role = this.ctx.getTags(ws)[0];

    if (role === "host") {
      // phone -> all browsers
      this.broadcast("client", message);
    } else {
      // browser -> phone
      const host = this.open("host")[0];
      if (host) {
        host.send(message);
      } else {
        ws.send(JSON.stringify({ type: "error", message: "Host not connected. Waiting..." }));
      }
    }
  }

  async webSocketClose(ws) {
    try { ws.close(1000, "Closing"); } catch {}
    this.onDisconnect(ws);
  }

  async webSocketError(ws) {
    try { ws.close(1011, "Error"); } catch {}
    this.onDisconnect(ws);
  }

  // Tell browsers when the phone is really gone (not just replaced)
  onDisconnect(ws) {
    const role = this.ctx.getTags(ws)[0];
    if (role === "host" && this.open("host").length === 0) {
      this.broadcast("client", JSON.stringify({ type: "host_disconnected" }));
    }
  }

  // Currently open sockets for a tag
  open(tag) {
    return this.ctx.getWebSockets(tag).filter((w) => w.readyState === WebSocket.OPEN);
  }

  broadcast(tag, data) {
    for (const w of this.open(tag)) {
      try { w.send(data); } catch {}
    }
  }
}

// ---------------------------------------------------------------------------
function landingPage() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Horus Relay</title>
  <style>
    body { font-family: system-ui; max-width: 800px; margin: 50px auto; padding: 20px; background: #0a0a0a; color: #e0e0e0; }
    h1 { color: #00ff9f; }
    pre { background: #1a1a1a; padding: 16px; border-radius: 8px; overflow-x: auto; }
    .step { margin: 20px 0; padding: 16px; background: #151515; border-left: 3px solid #00ff9f; }
  </style>
</head>
<body>
  <h1>Horus Terminal Relay</h1>
  <p>Private relay. A valid token is required to connect.</p>
  <div class="step"><h3>Host (phone)</h3><pre>wss://THIS-HOST/host?id=SESSION_ID&amp;token=TOKEN</pre></div>
  <div class="step"><h3>Client (browser)</h3><pre>wss://THIS-HOST/client?id=SESSION_ID&amp;token=TOKEN</pre></div>
</body>
</html>`;
        }
