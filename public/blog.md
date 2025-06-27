# Building a HackerNews OAuth Provider from First Principles

_How a weekend hack evolved into a production-ready OAuth provider (that unfortunately got blocked)_

What started as a simple question—"Can I programmatically authenticate with HackerNews?"—turned into building a complete OAuth 2.0 provider from scratch. Here's the journey from proof-of-concept to production roadblock, and why I need your help to make it work.

## Chapter 1: The "It Works on My Machine!" Moment

It all began with curiosity. HackerNews has user authentication, but no public API for login. Could I reverse-engineer their login flow?

After some investigation, I discovered something interesting: HN's login form accepts standard POST requests and returns predictable responses. A successful login triggers a 302 redirect to `/news` with a session cookie. A failed login stays on the login page.

Here's the proof-of-concept that got me excited:

```javascript
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/login") {
      // Convert form data and proxy to HackerNews
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
          Referer: "https://news.ycombinator.com/login",
        },
        body: params.toString(),
        redirect: "manual",
      });

      if (proxyResponse.status === 302) {
        const location = proxyResponse.headers.get("Location");
        if (location && location.includes("news")) {
          return new Response(
            "Login successful - would redirect to: " + location,
          );
        }
      }

      return new Response("Login failed", { status: 400 });
    }

    // Show login form
    return new Response(loginFormHTML, {
      headers: { "Content-Type": "text/html" },
    });
  },
};
```

**It worked!** Running locally, I could authenticate users with their HN credentials and capture their session tokens. The foundation was there.

## Chapter 2: Building a Real OAuth Provider

Once I proved the core concept worked, I got ambitious. Why not build a complete OAuth 2.0 provider around this? But I wanted to solve one of OAuth's biggest pain points: client registration.

### The Registration Problem

Traditional OAuth is painful for developers:

1. Sign up for yet another developer account
2. Register your application
3. Wait for approval
4. Get client ID and secret
5. Configure redirect URIs
6. Hope nothing changes

This friction kills many integrations before they start.

### The Solution: Your Domain IS Your Client ID

What if client registration was automatic? Here's my insight: **domain ownership provides natural client validation**.

```typescript
// No registration needed - your domain is your client ID!
const CLIENT_ID = "myapp.com";
const REDIRECT_URI = "https://myapp.com/callback";

// Security through domain ownership validation
function validateClient(clientId: string, redirectUri: string): boolean {
  const redirectUrl = new URL(redirectUri);

  // Must be HTTPS (except localhost for development)
  if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
    return false;
  }

  // Must redirect to same domain as client_id
  if (redirectUrl.hostname !== clientId) {
    return false;
  }

  return true; // You own the domain, you're the legitimate client
}
```

**The magic**: Anyone can use `myapp.com` as their client ID, but they can only redirect to URLs on `myapp.com`. Since they control that domain, they're the legitimate client. Zero registration, maximum security.

### Full OAuth 2.0 Implementation

I built out the complete Authorization Code flow with PKCE:

```typescript
// 1. Authorization endpoint
async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");

  // Validate domain-based client
  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
    });
  }

  if (!validateClient(clientId, redirectUri)) {
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

// 2. Token exchange endpoint
async function handleToken(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();
  const code = formData.get("code");
  const clientId = formData.get("client_id");

  // Get auth code data from Durable Object
  const authCodeDO = env.CODES.get(env.CODES.idFromName(`code:${code}`));
  const authData = await authCodeDO.getAuthData();

  if (!authData || authData.clientId !== clientId) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
    });
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

I also added MCP (Model Context Protocol) compliance, so AI agents can automatically discover and use the OAuth provider:

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
```

The system was elegant:

- ✅ Complete OAuth 2.0 flow with PKCE
- ✅ Zero client registration friction
- ✅ Domain-based security model
- ✅ MCP compliance for AI agents
- ✅ User profile extraction from HN
- ✅ Global edge deployment on Cloudflare Workers

## Chapter 3: The Production Reality Check

Everything worked beautifully in development. Then I deployed to production and... **403 Forbidden**.

```javascript
// This works perfectly on localhost
const proxyResponse = await fetch("https://news.ycombinator.com/login", {
  method: "POST",
  headers: minimalHeaders,
  body: params.toString(),
  redirect: "manual",
});

// In production: 403 Forbidden 😢
console.log("Response status:", proxyResponse.status); // 403
console.log("Response body:", await proxyResponse.text()); // "Sorry"
```

HackerNews blocks requests from Cloudflare Workers' IP ranges. My beautiful OAuth provider was dead in the water.

**The irony**: With correct credentials, the login still worked (HN would redirect properly), but with incorrect credentials or new registrations, it returned 403 instead of the proper login form. This made the user experience inconsistent and broken.

## Chapter 4: The Demo That Almost Was

Despite the production issues, I built a complete demo to show what's possible. Here's the minimal client implementation:

```javascript
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const OAUTH_PROVIDER = "https://hn.simplerauth.com";
    const CLIENT_ID = "news.gcombinator.com"; // My domain is my client ID!
    const REDIRECT_URI = "https://news.gcombinator.com/callback";

    // Handle OAuth callback
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");

      // Exchange code for token
      const tokenResponse = await fetch(`${OAUTH_PROVIDER}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code,
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
        }),
      });

      const { access_token } = await tokenResponse.json();

      // Redirect home with token cookie
      return new Response(null, {
        status: 302,
        headers: {
          Location: "/",
          "Set-Cookie": `access_token=${access_token}; HttpOnly; Secure; SameSite=Lax; Path=/`,
        },
      });
    }

    // Show user profile if authenticated
    const cookies = parseCookies(request.headers.get("Cookie") || "");
    if (cookies.access_token) {
      const userResponse = await fetch(`${OAUTH_PROVIDER}/api/user`, {
        headers: { Authorization: `Bearer ${cookies.access_token}` },
      });

      const { user } = await userResponse.json();

      return new Response(
        `
        <h1>Welcome, ${user.username}!</h1>
        <p>Karma: ${user.karma}</p>
        <p>Member since: ${new Date(
          user.created * 1000,
        ).toLocaleDateString()}</p>
        <button onclick="location.href='/logout'">Logout</button>
      `,
        {
          headers: { "Content-Type": "text/html" },
        },
      );
    }

    // Show login page
    const authUrl = new URL(`${OAUTH_PROVIDER}/authorize`);
    authUrl.searchParams.set("client_id", CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authUrl.searchParams.set("response_type", "code");

    return new Response(
      `
      <h1>HackerNews OAuth Demo</h1>
      <button onclick="location.href='${authUrl}'">Login with HackerNews</button>
    `,
      {
        headers: { "Content-Type": "text/html" },
      },
    );
  },
};
```

**This is the entire client implementation.** No registration, no API keys, no configuration—just start using it. The demo is available at [github.com/janwilmake/simplerauth-hn-oauth-client-demo](https://github.com/janwilmake/simplerauth-hn-oauth-client-demo).

## Chapter 5: Why This Matters (And Why I Need Your Help)

This isn't just about HackerNews OAuth. It's about reimagining how authentication should work:

### For Developers

- **Zero friction**: Start using OAuth immediately, no registration required
- **Standard protocol**: Works with existing OAuth libraries and tools
- **Secure by design**: Domain ownership provides natural client validation
- **Future-proof**: MCP compliance means AI agents can use it automatically

### For Users

- **Familiar login**: Uses the actual HackerNews login page they know
- **No new passwords**: Reuses existing HN credentials
- **Transparent process**: Clear about what's happening at each step
- **Privacy-focused**: Only accesses public profile information

### For the Ecosystem

- **Interoperability**: Standard OAuth means easy integration everywhere
- **No vendor lock-in**: Can migrate to other providers easily
- **Open source**: Full implementation available for audit and adaptation
- **Globally distributed**: Runs on edge infrastructure for speed

## The Ask: Help Me Get This Unblocked

The technical work is done. The OAuth provider is built, tested, and ready. The only blocker is HackerNews blocking Cloudflare Workers IP ranges.

**I need your help to:**

1. **Reach out to HackerNews** (hn@ycombinator.com) to request whitelisting for this OAuth provider
2. **Share this project** if you think it's valuable
3. **Connect me with someone at Y Combinator** who might be able to help

The full source code is available at:

- OAuth Provider: [github.com/janwilmake/hn-oauth-client-provider](https://github.com/janwilmake/hn-oauth-client-provider)
- Demo Client: [github.com/janwilmake/simplerauth-hn-oauth-client-demo](https://github.com/janwilmake/simplerauth-hn-oauth-client-demo)

You can also reach me directly at [@janwilmake](https://x.com/janwilmake).

## The Bigger Picture

This project proves that authentication doesn't have to be complicated. By questioning basic assumptions—Why does OAuth need client registration? Why can't domain ownership be enough?—we can build systems that are both more secure and more user-friendly.

The HackerNews OAuth provider works. It's secure, it's elegant, and it solves real problems. It just needs HackerNews to not block it.

Sometimes the best innovations get stuck on the most mundane obstacles. Help me get this one unstuck.

---

_If you work at Y Combinator, know someone who does, or just think this project is cool, please help spread the word. The future of frictionless authentication might depend on it._
