# Building a HackerNews OAuth Provider from First Principles

_Or: How I learned to stop worrying and love distributed authentication_

I've always been fascinated by authentication systems, especially OAuth. But every time I tried to understand OAuth 2.0, I got lost in the RFCs and abstract concepts. So I decided to build my own OAuth provider from scratch - using HackerNews as the identity source. This is the story of how I went from "OAuth is confusing" to "OAuth makes perfect sense" by building it step by step.

## The Problem: I Want to Build Cool Stuff with HN Data

Let's say I want to build a tool that analyzes your HackerNews comment history to generate insights about your interests. For this to work, I need access to your HN account. But how?

### Attempt 1: Just Ask for Passwords

The naive approach: just ask users for their HN username and password.

```html
<form>
  <input type="text" placeholder="HN Username" />
  <input type="password" placeholder="HN Password" />
  <button>Access My HN Data</button>
</form>
```

**Problems:**

- Users have to trust me with their actual HN password
- If my app gets hacked, all user passwords are compromised
- I get full access to their account (can post, change settings, etc.)
- No way to revoke access without changing their HN password

This is clearly terrible. We need something better.

### Attempt 2: Manual Token Generation

What if HackerNews had API tokens that users could generate manually?

```
1. User goes to HN settings
2. Generates an API token: "hn_token_abc123xyz"
3. Copies token into my app
4. My app uses token to access their data
```

This is more secure, but the user experience is awful. Nobody wants to manually copy-paste tokens every time they use an app.

## Enter OAuth: The Automated Token Dance

OAuth solves this by automating the token generation process. Instead of users manually creating tokens, my app can request them automatically - but only after the user explicitly grants permission.

Here's what I want to happen:

```
1. User clicks "Connect HN Account" in my app
2. They get redirected to a HN login page
3. HN asks: "Do you want to give MyApp access to your data?"
4. User clicks "Yes"
5. User gets redirected back to my app with access granted
6. My app can now access their HN data
```

But since HackerNews doesn't have OAuth built-in, I'll build my own OAuth provider that bridges to HN's cookie-based authentication.

## Building the OAuth Provider: Attack and Defend

Let me build this step by step, starting with a horribly insecure version and then fixing each vulnerability.

### Version 1: The "Trust Me Bro" Approach

```typescript
// Terrible first attempt
app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri } = req.query;

  // Just generate a token and redirect back
  const access_token = generateRandomToken();
  res.redirect(`${redirect_uri}?access_token=${access_token}`);
});
```

**Attack #1: Anyone can pretend to be anyone**

Malicious App could just call:

```
GET /authorize?client_id=TrustedApp&redirect_uri=https://malicious.com
```

And my provider would happily give them a token claiming to be TrustedApp!

**Fix: Require actual user authentication**

```typescript
app.get("/authorize", async (req, res) => {
  const { client_id, redirect_uri } = req.query;

  // Check if user is already logged in
  const user = await getCurrentUser(req);
  if (!user) {
    // Redirect to login page
    return res.redirect(`/login?redirect_to=${encodeURIComponent(req.url)}`);
  }

  // Show consent screen
  res.render("consent", { client_id, redirect_uri });
});
```

### Version 2: With Authentication, But Still Broken

Now I have a login flow that actually authenticates with HackerNews:

```typescript
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Forward login to HackerNews
  const hnResponse = await fetch("https://news.ycombinator.com/login", {
    method: "POST",
    body: new URLSearchParams({ acct: username, pw: password }),
  });

  if (hnResponse.ok) {
    // Extract HN session cookie
    const sessionCookie = extractSessionCookie(hnResponse);

    // Create our own access token
    const accessToken = await encrypt(sessionCookie, SECRET_KEY);

    // Redirect back to OAuth flow
    res.redirect(originalOAuthRequest);
  }
});
```

**Attack #2: Redirect URI hijacking**

Evil Corp could initiate an OAuth flow but point the redirect to their own domain:

```
https://myoauth.com/authorize?client_id=GoodApp&redirect_uri=https://evil-corp.com/steal-tokens
```

When the user approves, their access token gets sent to Evil Corp instead of GoodApp!

**Fix: Validate redirect URIs**

I need to ensure that the `redirect_uri` actually belongs to the `client_id`. Since I'm using domain-based client IDs, this is straightforward:

```typescript
function validateRedirectUri(clientId: string, redirectUri: string): boolean {
  const redirectUrl = new URL(redirectUri);

  // Redirect URI must be HTTPS
  if (redirectUrl.protocol !== "https:") return false;

  // Redirect URI must be on same domain as client_id
  if (redirectUrl.hostname !== clientId) return false;

  return true;
}
```

### Version 3: Secure Redirects, But Tokens in URLs

**Attack #3: Token leakage through browser history**

Even with proper redirect validation, access tokens in URLs are dangerous:

```
https://goodapp.com/callback?access_token=sensitive_token_here
```

This token will show up in:

- Browser history
- Server logs
- Referrer headers if the user clicks any external links

**Fix: Authorization Code Flow**

Instead of putting tokens directly in URLs, I'll use a two-step process:

1. Put a short-lived "authorization code" in the URL
2. App exchanges this code for an access token via a server-to-server request

```typescript
// Step 1: Give authorization code
app.get("/authorize", async (req, res) => {
  // ... authentication and validation ...

  const authCode = generateShortLivedCode();
  await storeAuthCode(authCode, { userId, clientId, redirectUri });

  res.redirect(`${redirectUri}?code=${authCode}`);
});

// Step 2: Exchange code for token
app.post("/token", async (req, res) => {
  const { code, client_id, redirect_uri } = req.body;

  const authData = await getAuthCode(code);
  if (!authData || authData.clientId !== client_id) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  const accessToken = await generateAccessToken(authData.userId);
  res.json({ access_token: accessToken, token_type: "bearer" });
});
```

### Version 4: Authorization Codes, But Still Vulnerable

**Attack #4: Code interception and replay**

If someone can intercept the authorization code (through network sniffing, malware, etc.), they could exchange it for an access token before the legitimate app does.

**Fix: Proof Key for Code Exchange (PKCE)**

The app generates a random secret, hashes it, and includes the hash in the initial request. When exchanging the code, it provides the original secret to prove it's the same client:

```typescript
// Client side: Generate PKCE challenge
const codeVerifier = generateRandomString();
const codeChallenge = sha256(codeVerifier);

// Initial request includes challenge
const authUrl =
  `https://myoauth.com/authorize?` +
  `client_id=myapp.com&` +
  `redirect_uri=https://myapp.com/callback&` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256`;

// Later, when exchanging code:
fetch("/token", {
  method: "POST",
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: authCode,
    client_id: "myapp.com",
    code_verifier: codeVerifier, // Original secret
  }),
});
```

On the server side:

```typescript
app.post("/token", async (req, res) => {
  const { code, code_verifier, client_id } = req.body;

  const authData = await getAuthCode(code);

  // Verify PKCE
  const expectedChallenge = sha256(code_verifier);
  if (authData.codeChallenge !== expectedChallenge) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  // ... rest of token exchange ...
});
```

### Attack #5: CSRF - The Sneaky Account Linkage

**Attack: Cross-Site Request Forgery**

Evil Corp could trick a user into unknowingly linking Evil Corp's HN account to their own app account:

1. Evil Corp starts OAuth flow with my app, gets redirected to login
2. Instead of logging in, they send the authorization URL to victims
3. Victim clicks link, sees it's my legitimate domain, logs in with their own HN account
4. But the OAuth flow was initiated by Evil Corp, so victim's HN account gets linked to Evil Corp's app account
5. Victim uploads private data, thinking it's going to their own account, but it actually goes to Evil Corp's account

**Fix: State parameter**

The client includes a random `state` parameter that gets round-tripped through the entire flow:

```typescript
// Client generates random state
const state = generateRandomString();
sessionStorage.setItem("oauth_state", state);

const authUrl =
  `https://myoauth.com/authorize?` +
  `client_id=myapp.com&` +
  `state=${state}&` +
  `...`;

// In callback, verify state matches
const urlParams = new URLSearchParams(window.location.search);
const returnedState = urlParams.get("state");
const expectedState = sessionStorage.getItem("oauth_state");

if (returnedState !== expectedState) {
  throw new Error("CSRF attack detected!");
}
```

## The Final, Secure Implementation

After all these fixes, here's what my OAuth flow looks like:

```typescript
// 1. Authorization request with PKCE and state
app.get("/authorize", async (req, res) => {
  const { client_id, redirect_uri, code_challenge, state } = req.query;

  // Validate client and redirect URI
  if (
    !isValidDomain(client_id) ||
    !validateRedirectUri(client_id, redirect_uri)
  ) {
    return res.status(400).send("Invalid client or redirect URI");
  }

  // Check authentication
  const user = await getCurrentUser(req);
  if (!user) {
    return res.redirect(
      `/login?state=${encodeURIComponent(
        JSON.stringify({
          clientId: client_id,
          redirectUri: redirect_uri,
          codeChallenge: code_challenge,
          state,
        }),
      )}`,
    );
  }

  // Generate authorization code
  const authCode = generateRandomString();
  await storeDurableObject(authCode, {
    userId: user.id,
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
  });

  // Redirect with code and state
  const callbackUrl = new URL(redirect_uri);
  callbackUrl.searchParams.set("code", authCode);
  if (state) callbackUrl.searchParams.set("state", state);

  res.redirect(callbackUrl.toString());
});

// 2. Token exchange with PKCE verification
app.post("/token", async (req, res) => {
  const { grant_type, code, client_id, code_verifier } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  // Get and validate auth code
  const authData = await getDurableObject(code);
  if (!authData || authData.expiresAt < Date.now()) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  // Verify PKCE
  const expectedChallenge = await sha256(code_verifier);
  if (authData.codeChallenge !== expectedChallenge) {
    return res.status(400).json({ error: "invalid_grant" });
  }

  // Generate access token (encrypted HN session)
  const user = await getUser(authData.userId);
  const accessToken = await encrypt(user.hnSessionCookie, HN_SESSION_KEY);

  // Clean up auth code
  await deleteDurableObject(code);

  res.json({
    access_token: accessToken,
    token_type: "bearer",
    scope: "read",
  });
});
```

## The Magic: No Client Registration Required

Here's the clever part of my implementation: I use the client's domain name as their `client_id`. This eliminates the need for a registration process while maintaining security:

- `client_id`: `myapp.com`
- Default `redirect_uri`: `https://myapp.com/callback`
- Validation: Redirect URI must be on same domain as client_id

This means any developer can integrate with my OAuth provider immediately, without signing up or getting API keys. They just use their domain as the client ID.

## Usage Examples

### For App Developers

```javascript
// 1. Redirect user to authorization
const authUrl =
  "https://hn.simplerauth.com/authorize?" +
  new URLSearchParams({
    client_id: "myapp.com",
    redirect_uri: "https://myapp.com/callback",
    response_type: "code",
    state: randomState,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });

window.location.href = authUrl;

// 2. Handle callback and exchange code for token
const code = new URLSearchParams(window.location.search).get("code");

const tokenResponse = await fetch("https://hn.simplerauth.com/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: code,
    client_id: "myapp.com",
    code_verifier: codeVerifier,
  }),
});

const { access_token } = await tokenResponse.json();

// 3. Use token to access user data
const userResponse = await fetch("https://hn.simplerauth.com/api/user", {
  headers: { Authorization: `Bearer ${access_token}` },
});
```

### For Simple Login

```typescript
// Using the helper wrapper for enforced authentication
export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    // ctx.user is guaranteed to exist and contains HN user data
    return new Response(
      `
      <h1>Welcome, ${ctx.user.username}!</h1>
      <p>Karma: ${ctx.user.karma}</p>
      <p>Member since: ${new Date(ctx.user.created).toLocaleDateString()}</p>
    `,
      {
        headers: { "Content-Type": "text/html" },
      },
    );
  }),
};
```

## Why This Approach Works

1. **No Registration Friction**: Developers can start using it immediately
2. **Domain-Based Security**: Using domains as client IDs provides natural validation
3. **Standard OAuth 2.0**: Follows established patterns that developers already know
4. **HN Integration**: Leverages HN's existing authentication without requiring API changes
5. **MCP Compliance**: Includes proper metadata endpoints for AI agents and other automated clients

## The Technical Stack

- **Cloudflare Workers**: For the OAuth endpoints and logic
- **Durable Objects**: For storing authorization codes and user sessions
- **Web Crypto API**: For PKCE and token encryption
- **HackerNews Scraping**: For extracting user profile data after authentication

The entire provider runs on Cloudflare's edge network, making it fast and globally distributed.

## Lessons Learned

Building OAuth from scratch taught me that security isn't about perfect solutions - it's about understanding threats and systematically addressing them. Each "attack" I fixed made the system more robust, but also more complex. The key is finding the right balance between security and usability.

The domain-based client ID approach was the breakthrough that made this practical. It eliminates the biggest friction point (client registration) while maintaining security through natural domain ownership validation.

## Try It Yourself

The full implementation is open source and deployed at [hn.simplerauth.com](https://hn.simplerauth.com). You can use it in your own projects or study the code to understand how OAuth really works under the hood.

Sometimes the best way to understand something is to build it yourself, break it, fix it, and repeat until it's bulletproof. That's exactly what I did with OAuth, and now it makes complete sense.

---

_Want to see the code? Check out the [GitHub repository](https://github.com/janwilmake/hn-oauth-client-provider) or try the [live demo](https://hn.simplerauth.com)._
