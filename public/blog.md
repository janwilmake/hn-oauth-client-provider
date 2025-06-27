# Building a HackerNews OAuth Provider: From Proxy POC to Production

Or: How a simple login proxy evolved into a full OAuth provider that requires no client registration

I was working on a project that needed HackerNews authentication when I stumbled upon something interesting: HN's login form can be used programmatically. This discovery led me down a rabbit hole that ended with building a complete OAuth 2.0 provider. Here's how it all unfolded.

## The Lightbulb Moment: HN Login as a Proxy

It started with a simple question: "Can I proxy HackerNews login requests?" Turns out, the answer is yes:

```javascript
// The POC that started it all
export default {
  async fetch(request, env, ctx) {
    if (request.method === "POST" && url.pathname === "/login") {
      // Convert form data and forward to HN
      const formData = await request.formData();
      const params = new URLSearchParams();
      for (const [key, value] of formData.entries()) {
        params.append(key, value);
      }

      const proxyResponse = await fetch("https://news.ycombinator.com/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Origin: "https://news.ycombinator.com",
          Referer: "https://news.ycombinator.com/",
        },
        body: params.toString(),
        redirect: "manual",
      });

      if (proxyResponse.status === 302) {
        const location = proxyResponse.headers.get("Location");
        if (location && location.includes("news")) {
          return new Response("Login successful!", { status: 200 });
        }
      }
    }

    // Show login form
    return new Response(loginFormHTML, {
      headers: { "Content-Type": "text/html" },
    });
  },
};
```

**The breakthrough**: HackerNews returns a 302 redirect to `/news` on successful login, and includes a session cookie in the response headers. This meant I could programmatically authenticate users and capture their session tokens!

## From Proxy to OAuth Provider

Once I realized I could authenticate users programmatically, the next logical step was building a proper OAuth provider around it. But I wanted to solve a fundamental problem with OAuth: client registration.

### The Registration Problem

Traditional OAuth providers require developers to:

1. Sign up for an account
2. Register their application
3. Get a client ID and secret
4. Configure redirect URIs
5. Wait for approval

This creates friction that kills many integrations before they start.

### The Solution: Domain-Based Client IDs

What if the client's domain _is_ their client ID? Here's how it works:

```typescript
// No registration required!
const CLIENT_ID = "myapp.com";
const REDIRECT_URI = "https://myapp.com/callback";

// Security through domain ownership validation
function validateRedirectUri(clientId: string, redirectUri: string): boolean {
  const redirectUrl = new URL(redirectUri);

  // Must be HTTPS (except localhost for dev)
  if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
    return false;
  }

  // Must be on same domain as client_id
  if (redirectUrl.hostname !== clientId) {
    return false;
  }

  return true;
}
```

**The magic**: Anyone can use `myapp.com` as their client ID, but they can only redirect to URLs on `myapp.com`. Since they control that domain, they're the legitimate client. No registration needed!

## The Complete OAuth Implementation

Here's how I built the full OAuth 2.0 Authorization Code flow with PKCE:

### 1. Authorization Endpoint

```typescript
async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");

  // Validate domain-based client ID
  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
    });
  }

  // Validate redirect URI matches client domain
  if (!validateRedirectUri(clientId, redirectUri)) {
    return new Response(
      "Invalid redirect_uri: must be on same domain as client_id",
      { status: 400 },
    );
  }

  // Check if user is already authenticated
  const accessToken = getAccessToken(request);
  if (accessToken) {
    return await createAuthCodeAndRedirect(
      env,
      clientId,
      redirectUri,
      state,
      accessToken,
    );
  }

  // Redirect to HN login
  const loginState = btoa(JSON.stringify({ clientId, redirectUri, state }));
  return new Response(null, {
    status: 302,
    headers: { Location: `/login?state=${encodeURIComponent(loginState)}` },
  });
}
```

### 2. Login Handler (The Proxy Magic)

```typescript
async function handleLogin(request: Request, env: Env): Promise<Response> {
  if (request.method === "POST") {
    const formData = await request.formData();
    const params = new URLSearchParams();
    for (const [key, value] of formData.entries()) {
      params.append(key, value);
    }

    // Forward to HackerNews
    const proxyResponse = await fetch("https://news.ycombinator.com/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: "https://news.ycombinator.com",
        Referer: "https://news.ycombinator.com/",
      },
      body: params.toString(),
      redirect: "manual",
    });

    if (proxyResponse.status === 302) {
      const location = proxyResponse.headers.get("Location");
      if (location && location.includes("news")) {
        // Success! Extract session cookie
        const setCookieHeader = proxyResponse.headers.get("Set-Cookie");
        const hnSessionCookie = extractSessionCookie(setCookieHeader);

        // Get username and fetch user profile
        const username = params.get("acct");
        const user = await fetchHNUserProfile(username, hnSessionCookie);

        // Create encrypted access token
        const encryptedAccessToken = await encrypt(
          hnSessionCookie,
          env.HN_SESSION_KEY,
        );

        // Store user data in Durable Object
        const userDOId = env.CODES.idFromName(`user:${encryptedAccessToken}`);
        const userDO = env.CODES.get(userDOId);
        await userDO.setUser(user, hnSessionCookie, encryptedAccessToken);

        return await handleOAuthSuccess(request, env, encryptedAccessToken);
      }
    }
  }

  // Show login form
  return new Response(loginFormHTML, {
    headers: { "Content-Type": "text/html" },
  });
}
```

### 3. Token Exchange

```typescript
async function handleToken(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const code = formData.get("code");
  const clientId = formData.get("client_id");
  const codeVerifier = formData.get("code_verifier");

  // Get auth code data from Durable Object
  const authCodeDO = env.CODES.get(env.CODES.idFromName(`code:${code}`));
  const authData = await authCodeDO.getAuthData();

  if (!authData || authData.clientId !== clientId) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
    });
  }

  // Verify PKCE (if provided)
  if (codeVerifier && authData.codeChallenge) {
    const expectedChallenge = await sha256(codeVerifier);
    if (authData.codeChallenge !== expectedChallenge) {
      return new Response(JSON.stringify({ error: "invalid_grant" }), {
        status: 400,
      });
    }
  }

  return new Response(
    JSON.stringify({
      access_token: authData.access_token,
      token_type: "bearer",
      scope: "read",
    }),
  );
}
```

## MCP Compliance: OAuth for AI Agents

One of the coolest features is full Model Context Protocol (MCP) compliance. This means AI agents can automatically discover and use the OAuth provider:

```typescript
// OAuth 2.0 Authorization Server Metadata (RFC 8414)
if (path === "/.well-known/oauth-authorization-server") {
  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["read"],
    token_endpoint_auth_methods_supported: ["none"],
  };

  return new Response(JSON.stringify(metadata), {
    headers: { "Content-Type": "application/json" },
  });
}

// OAuth 2.0 Protected Resource Metadata (RFC 9728)
if (path === "/.well-known/oauth-protected-resource") {
  const metadata = {
    resource: baseUrl,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    resource_documentation: `${baseUrl}`,
  };

  return new Response(JSON.stringify(metadata), {
    headers: { "Content-Type": "application/json" },
  });
}
```

## Using the OAuth Provider

### For Client Apps

```javascript
// 1. Start OAuth flow
const authUrl = new URL("https://hn.simplerauth.com/authorize");
authUrl.searchParams.set("client_id", "news.gcombinator.com");
authUrl.searchParams.set(
  "redirect_uri",
  "https://news.gcombinator.com/callback",
);
authUrl.searchParams.set("response_type", "code");
authUrl.searchParams.set("state", generateRandomState());

window.location.href = authUrl.toString();

// 2. Handle callback
async function handleCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const code = urlParams.get("code");

  // Exchange code for token
  const tokenResponse = await fetch("https://hn.simplerauth.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      client_id: "news.gcombinator.com",
      redirect_uri: "https://news.gcombinator.com/callback",
    }),
  });

  const { access_token } = await tokenResponse.json();

  // Use token to get user info
  const userResponse = await fetch("https://hn.simplerauth.com/api/user", {
    headers: { Authorization: `Bearer ${access_token}` },
  });

  const userData = await userResponse.json();
  console.log(userData.user); // HN user profile
}
```

### For Cloudflare Workers (Simplified)

```typescript
import { withSimplerAuth } from "./oauth-provider";

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      // ctx.user is guaranteed to exist and contains HN user data
      const { username, karma, created, about } = ctx.user;

      return new Response(
        `
      <h1>Welcome, ${username}!</h1>
      <p>Karma: ${karma}</p>
      <p>Member since: ${new Date(created * 1000).toLocaleDateString()}</p>
      ${about ? `<p>About: ${about}</p>` : ""}
    `,
        {
          headers: { "Content-Type": "text/html" },
        },
      );
    },
    {
      isLoginRequired: true, // Enforce authentication
      scope: "read",
      sameSite: "Lax",
    },
  ),
};
```

## The Architecture: Cloudflare Workers + Durable Objects

The entire system runs on Cloudflare's edge:

- **Workers**: Handle OAuth endpoints, login proxy, and token validation
- **Durable Objects**: Store authorization codes and user sessions
- **Web Crypto API**: PKCE implementation and token encryption
- **No Database**: Everything is serverless and distributed

```typescript
export class CodeDO extends DurableObject {
  async setAuthData(
    hnSessionCookie: string,
    encryptedAccessToken: string,
    clientId: string,
    redirectUri: string,
  ) {
    await this.storage.put("data", {
      hn_session_cookie: hnSessionCookie,
      access_token: encryptedAccessToken,
      clientId,
      redirectUri,
    });

    // Auto-expire in 10 minutes
    this.storage.setAlarm(Date.now() + 10 * 60 * 1000);
  }

  async alarm() {
    // Clean up expired codes
    await this.storage.deleteAll();
  }
}
```

## Security Features

1. **Domain-based client validation**: Only domain owners can use their domain as client_id
2. **PKCE support**: Prevents authorization code interception
3. **State parameter**: CSRF protection
4. **Token encryption**: HN session cookies are encrypted before storage
5. **Automatic cleanup**: Authorization codes expire after 10 minutes
6. **HTTPS enforcement**: All redirects must use HTTPS (except localhost)

## Why This Approach Works

### For Developers

- **Zero registration friction**: Start using it immediately
- **Standard OAuth 2.0**: Works with existing libraries and tools
- **Secure by design**: Domain ownership provides natural validation
- **MCP compatible**: AI agents can discover and use it automatically

### For Users

- **Familiar login**: Uses actual HackerNews login page
- **No new passwords**: Reuses existing HN credentials
- **Transparent process**: Clear what's happening at each step
- **Revocable access**: Can logout to revoke access

### For the Ecosystem

- **No vendor lock-in**: Standard OAuth means easy migration
- **Globally distributed**: Runs on Cloudflare's edge network
- **Open source**: Full implementation available for audit
- **Extensible**: Can be adapted for other cookie-based auth systems

## The Live Demo

I built a complete demo app that shows the OAuth flow in action:

```javascript
// Client app running at news.gcombinator.com
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/callback") {
      return handleOAuthCallback(request);
    }

    const accessToken = getAccessTokenFromCookie(request);
    if (accessToken) {
      return showUserProfile(accessToken);
    }

    return showLoginPage();
  },
};

async function showUserProfile(accessToken) {
  const userResponse = await fetch("https://hn.simplerauth.com/api/user", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const userData = await userResponse.json();
  const user = userData.user;

  return new Response(
    `
    <h1>Welcome to HackerNews OAuth Demo</h1>
    <div class="user-info">
      <h2>User Info</h2>
      <p><strong>Username:</strong> ${user.username}</p>
      <p><strong>Karma:</strong> ${user.karma}</p>
      <p><strong>User ID:</strong> ${user.id}</p>
      ${user.about ? `<p><strong>About:</strong> ${user.about}</p>` : ""}
    </div>
    <button onclick="window.location.href='/logout'">Logout</button>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}
```

## From POC to Production

What started as a 50-line proxy script evolved into a full OAuth 2.0 provider with:

- ✅ Complete Authorization Code flow with PKCE
- ✅ Domain-based client validation (no registration needed)
- ✅ MCP compliance for AI agents
- ✅ Automatic token encryption and session management
- ✅ User profile extraction from HN
- ✅ Comprehensive security features
- ✅ Global edge deployment
- ✅ Open source implementation

## The Key Insight

The breakthrough wasn't just that HN login could be proxied—it was realizing that domain ownership provides natural client validation. This eliminates the biggest friction point in OAuth (client registration) while maintaining security.

By treating domains as client IDs, developers can integrate immediately without any setup, but they can only redirect to URLs they control. It's elegant, secure, and removes barriers to adoption.

## Try It Yourself

The OAuth provider is live at [hn.simplerauth.com](https://hn.simplerauth.com), and you can see the demo client at [news.gcombinator.com](https://news.gcombinator.com).

Full source code is available on [GitHub](https://github.com/janwilmake/hn-oauth-client-provider), including:

- Complete OAuth provider implementation
- Example client applications
- Deployment instructions for Cloudflare Workers
- Security analysis and threat model

Sometimes the best solutions come from questioning assumptions. Why does OAuth need client registration? Why can't domain ownership be enough? Why can't we proxy existing auth systems?

This project proves that with a little creativity, you can build something that's both more secure and more user-friendly than the traditional approach.

---

Want to build your own OAuth provider? Check out the [full implementation](https://github.com/janwilmake/hn-oauth-client-provider) or try the [live demo](https://hn.simplerauth.com).
