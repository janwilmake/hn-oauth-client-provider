# HackerNews OAuth Provider

[![janwilmake/hn-oauth-client-provider context](https://badge.forgithub.com/janwilmake/hn-oauth-client-provider/tree/main/README.md)](https://uithub.com/janwilmake/hn-oauth-client-provider/tree/main/README.md)

> [!WARNING]
> This works in localhost, but in production on a cloudflare worker you'll quickly get ratelimited, forbidding any login, thus, unfortunatly, this concept won't work unless HN would whitelist me. If you want HN OAuth with a script as simple as [this](https://github.com/janwilmake/simplerauth-hn-oauth-client-demo), please tell HackerNews about this project and [reach out to me](https://x.com/janwilmake)

This HackerNews OAuth client-provider uses the client's domain name as the client_id and automatically derives the `redirect_uri` from it (e.g., `https://example.com/callback`), eliminating the need for client registration while maintaining security through domain validation.

## Setup

1. Installation:

```bash
npm i simplerauth-hn-provider
```

2. Set environment variables:

   - `HN_SESSION_KEY`: Secret key for encrypting session data

3. Add to your worker:

### Direct flow

```typescript
import { handleOAuth, getAccessToken, CodeDO } from "simplerauth-hn-provider";
export { CodeDO };
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) return oauthResponse;

    // Check if user is authenticated
    const accessToken = getAccessToken(request);
    if (!accessToken) {
      // Redirect users to `/authorize?redirect_to=/dashboard` for simple login.
      return Response.redirect(
        "/authorize?redirect_to=" + encodeURIComponent(request.url),
      );
    }

    // Your app logic here
    return new Response("Hello authenticated user!");
  },
};
```

### Enforced Authentication Flow:

```typescript
import { CodeDO, withSimplerAuth } from "./hn-oauth-client-provider";
export { CodeDO };
export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    return new Response(
      `<html><body>
        <h1>HackerNews OAuth Demo</h1>
        <p>Welcome, ${ctx.user.username}!</p>
        <p>Karma: ${ctx.user.karma}</p>
        <a href="/logout">Logout</a><br>
        <a href="/provider">Try provider flow example</a>
      </body></html>`,
      { headers: { "Content-Type": "text/html" } },
    );
  }),
};
```

### OAuth Provider Flow

Other apps can use standard OAuth 2.0 flow with your worker as the provider. See [public/provider.html](public/provider.html) for a client example.

### Client Integration Steps

1. **Authorization Request**: Redirect users to your provider's authorize endpoint:

```
https://oauth.gcombinator.com/authorize?client_id=CLIENT_DOMAIN&redirect_uri=REDIRECT_URI&response_type=code&state=RANDOM_STATE
```

Parameters:

- `client_id`: Your client's domain (e.g., `example.com`)
- `redirect_uri`: Where to redirect after auth (must be HTTPS and on same domain as client_id)
- `response_type`: Must be `code`
- `state`: Random string for CSRF protection

2. **Handle Authorization Callback**: After user authorizes, they'll be redirected to your `redirect_uri` with:

```
https://your-app.com/callback?code=AUTH_CODE&state=YOUR_STATE
```

3. **Exchange Code for Token**: Make a POST request to exchange the authorization code:

```javascript
const response = await fetch("https://oauth.gcombinator.com/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code: "AUTH_CODE_FROM_CALLBACK",
    client_id: "your-domain.com",
    redirect_uri: "https://your-domain.com/callback",
  }),
});

const { access_token } = await response.json();
```

4. **Use Access Token**: Use the token to make API requests to get user info:

```javascript
const userResponse = await fetch("https://oauth.gcombinator.com/api/user", {
  headers: { Authorization: `Bearer ${access_token}` },
});
```

### Security Notes

- Client domains are validated - `client_id` must be a valid domain
- Redirect URIs must be HTTPS and on the same domain as `client_id`
- Authorization codes expire after 10 minutes
- No client registration required - the domain serves as the client identifier
- Uses HackerNews login system for authentication

## Routes

- `/authorize` - OAuth authorization endpoint
- `/token` - OAuth token endpoint
- `/login` - HackerNews login form and handler
- `/logout` - Logout and clear session
- `/api/user` - Get authenticated user info (for OAuth clients)

## Features

- **Domain-based OAuth**: No client registration needed
- **HackerNews Integration**: Uses real HN accounts and login system
- **MCP-compliant**: Implements OAuth 2.0 server metadata endpoints
- **User Profile Data**: Extracts karma, creation date, and about info
- **Secure Token Storage**: Encrypted access tokens using Durable Objects
- **CORS Support**: Ready for cross-origin OAuth flows

## Notes

This provider acts as a bridge between HackerNews's cookie-based authentication and standard OAuth 2.0 flows. It extracts user profile information by parsing HN's user profile pages after successful authentication.

For agent-friendly authentication, the provider returns appropriate WWW-Authenticate headers with login URLs when authentication is required.
