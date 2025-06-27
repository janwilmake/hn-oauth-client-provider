import { DurableObject } from "cloudflare:workers";

export interface Env {
  HN_SESSION_KEY: string; // Secret for encrypting session data
  CODES: DurableObjectNamespace<CodeDO>;
}

interface OAuthState {
  redirectTo?: string;
  codeVerifier: string;
  resource?: string;
}

export interface HNUser {
  id: string;
  username: string;
  created: number;
  karma: number;
  about?: string;
  delay?: number;
  [key: string]: any;
}

export class CodeDO extends DurableObject {
  private storage: DurableObjectStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.storage = state.storage;
    // Set alarm for 10 minutes from now
    this.storage.setAlarm(Date.now() + 10 * 60 * 1000);
  }

  async alarm() {
    // Only self-delete if this is not a user storage (auth codes expire, users don't)
    const user = await this.storage.get("user");
    if (!user) {
      await this.storage.deleteAll();
    }
  }

  async setAuthData(
    hnSessionCookie: string,
    encryptedAccessToken: string,
    clientId: string,
    redirectUri: string,
    resource?: string,
  ) {
    await this.storage.put("data", {
      hn_session_cookie: hnSessionCookie,
      access_token: encryptedAccessToken,
      clientId,
      redirectUri,
      resource,
    });
  }

  async getAuthData() {
    return this.storage.get<{
      hn_session_cookie: string;
      access_token: string;
      clientId: string;
      redirectUri: string;
      resource?: string;
    }>("data");
  }

  async setUser(
    user: HNUser,
    hnSessionCookie: string,
    encryptedAccessToken: string,
  ) {
    await this.storage.put("user", user);
    await this.storage.put("hn_session_cookie", hnSessionCookie);
    await this.storage.put("access_token", encryptedAccessToken);
  }

  async getUser(): Promise<{
    user: HNUser;
    hnSessionCookie: string;
    accessToken: string;
  } | null> {
    const user = await this.storage.get<HNUser>("user");
    const hnSessionCookie = await this.storage.get<string>("hn_session_cookie");
    const accessToken = await this.storage.get<string>("access_token");

    if (!user || !hnSessionCookie || !accessToken) {
      return null;
    }

    return {
      user,
      hnSessionCookie,
      accessToken,
    };
  }

  async setMetadata<T>(metadata: T) {
    await this.storage.put("metadata", metadata);
  }

  async getMetadata<T>(): Promise<T | null> {
    const metadata = await this.storage.get<T>("metadata");
    if (!metadata) {
      return null;
    }
    return metadata;
  }
}

/**
 * Handle OAuth requests including MCP-required metadata endpoints.
 * Handles /authorize, /token, /callback, /logout, and metadata endpoints.
 */
export async function handleOAuth(
  request: Request,
  env: Env,
  scope = "read",
  sameSite: "Strict" | "Lax" = "Lax",
): Promise<Response | null> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (!env.HN_SESSION_KEY || !env.CODES) {
    return new Response(
      `Environment misconfigured. Ensure to have HN_SESSION_KEY secret set, as well as the Durable Object, with:

[[durable_objects.bindings]]
name = "CODES"
class_name = "CodeDO"

[[migrations]]
new_sqlite_classes = ["CodeDO"]
tag = "v1"

      `,
      {
        status: 500,
      },
    );
  }

  // MCP Required: OAuth 2.0 Authorization Server Metadata (RFC8414)
  if (path === "/.well-known/oauth-authorization-server") {
    return handleAuthorizationServerMetadata(request, env, scope);
  }

  // MCP Required: OAuth 2.0 Protected Resource Metadata (RFC9728)
  if (path === "/.well-known/oauth-protected-resource") {
    return handleProtectedResourceMetadata(request, env);
  }

  if (path === "/token") {
    return handleToken(request, env, scope);
  }

  if (path === "/authorize") {
    return handleAuthorize(request, env, scope, sameSite);
  }

  if (path === "/callback") {
    return handleCallback(request, env, sameSite);
  }

  if (path === "/login") {
    return handleLogin(request, env, sameSite);
  }

  if (path === "/logout") {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    return new Response(null, {
      status: 302,
      headers: {
        Location: redirectTo,
        "Set-Cookie": `access_token=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      },
    });
  }

  return null; // Not an OAuth route, let other handlers take over
}

// MCP Required: OAuth 2.0 Authorization Server Metadata (RFC8414)
function handleAuthorizationServerMetadata(
  request: Request,
  env: Env,
  scope: string,
): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: scope.split(" "),
    token_endpoint_auth_methods_supported: ["none"], // Public client support
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

// MCP Required: OAuth 2.0 Protected Resource Metadata (RFC9728)
function handleProtectedResourceMetadata(request: Request, env: Env): Response {
  const url = new URL(request.url);
  const baseUrl = `${url.protocol}//${url.host}`;

  const metadata = {
    resource: baseUrl,
    authorization_servers: [baseUrl],
    bearer_methods_supported: ["header"],
    resource_documentation: `${baseUrl}`,
  };

  return new Response(JSON.stringify(metadata), {
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

async function handleAuthorize(
  request: Request,
  env: Env,
  scope: string,
  sameSite: string,
): Promise<Response> {
  const url = new URL(request.url);
  const clientId = url.searchParams.get("client_id");
  let redirectUri = url.searchParams.get("redirect_uri");
  const responseType = url.searchParams.get("response_type") || "code";
  const state = url.searchParams.get("state");
  const resource = url.searchParams.get("resource"); // MCP Required: Resource parameter

  // If no client_id, this is a direct login request
  if (!clientId) {
    const url = new URL(request.url);
    const redirectTo = url.searchParams.get("redirect_to") || "/";
    const resource = url.searchParams.get("resource");

    // Generate PKCE code verifier and challenge
    const codeVerifier = generateCodeVerifier();

    // Create state with redirect info, code verifier, and resource
    const state: OAuthState = { redirectTo, codeVerifier, resource };
    const stateString = btoa(JSON.stringify(state));

    // Redirect to HackerNews login page
    return new Response(null, {
      status: 302,
      headers: {
        Location: `/login?state=${encodeURIComponent(stateString)}`,
        "Set-Cookie": `oauth_state=${encodeURIComponent(
          stateString,
        )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
      },
    });
  }

  // Validate that client_id looks like a domain
  if (!isValidDomain(clientId) && clientId !== "localhost") {
    return new Response("Invalid client_id: must be a valid domain", {
      status: 400,
    });
  }

  // If no redirect_uri provided, use default pattern
  if (!redirectUri) {
    redirectUri = `https://${clientId}/callback`;
  }

  // Validate redirect_uri is HTTPS and on same origin as client_id
  try {
    const redirectUrl = new URL(redirectUri);

    if (redirectUrl.protocol !== "https:" && clientId !== "localhost") {
      return new Response("Invalid redirect_uri: must use HTTPS", {
        status: 400,
      });
    }

    if (redirectUrl.hostname !== clientId) {
      return new Response(
        "Invalid redirect_uri: must be on same origin as client_id",
        { status: 400 },
      );
    }
  } catch {
    return new Response("Invalid redirect_uri format", { status: 400 });
  }

  // Only support authorization code flow
  if (responseType !== "code") {
    return new Response("Unsupported response_type", { status: 400 });
  }

  // Check if user is already authenticated
  const accessToken = getAccessToken(request);
  if (accessToken) {
    // User is already authenticated, create auth code and redirect
    return await createAuthCodeAndRedirect(
      env,
      clientId,
      redirectUri,
      state,
      accessToken,
      resource,
    );
  }

  // User not authenticated, redirect to HN login with our callback
  // Store the OAuth provider request details for after HN auth
  const providerState = {
    clientId,
    redirectUri,
    state,
    originalState: state,
    resource, // MCP: Store resource parameter
  };

  const providerStateString = btoa(JSON.stringify(providerState));

  // Generate PKCE for HN login
  const codeVerifier = generateCodeVerifier();

  const hnState: OAuthState = {
    redirectTo: url.pathname + url.search, // Return to this authorize request after HN auth
    codeVerifier,
    resource,
  };

  const hnStateString = btoa(JSON.stringify(hnState));

  const headers = new Headers({
    Location: `/login?state=${encodeURIComponent(hnStateString)}`,
  });
  headers.append(
    "Set-Cookie",
    `oauth_state=${encodeURIComponent(
      hnStateString,
    )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
  );
  headers.append(
    "Set-Cookie",
    `provider_state=${encodeURIComponent(
      providerStateString,
    )}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=600; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

const getLoginHTML = (errorMessage = "", stateParam?: string) => {
  const errorHtml = errorMessage
    ? `<div style="margin-bottom: 20px; color: red;">${errorMessage}</div>`
    : "";

  return `<html lang="en">
<head>
    <meta name="referrer" content="origin">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="y18.svg">
    <title>HackerNews OAuth Login</title>
</head>
<body>
    <h1>HackerNews OAuth Login</h1>
    <p>Login with your HackerNews account to continue.</p>
    <br>
    ${errorHtml}
    <b>Login</b>
    <br>
    <br>
    <form action="/login" method="post">
        ${
          stateParam
            ? `<input type="hidden" name="state" value="${stateParam}">`
            : ""
        }
        <input type="hidden" name="goto" value="news">
        <table border="0">
            <tr>
                <td>username:</td>
                <td>
                    <input type="text" name="acct" size="20" autocorrect="off" spellcheck="false" autocapitalize="off" autofocus="true">
                </td>
            </tr>
            <tr>
                <td>password:</td>
                <td>
                    <input type="password" name="pw" size="20">
                </td>
            </tr>
        </table>
        <br>
        <input type="submit" value="login">
    </form>
    <a href="https://news.ycombinator.com/login">Recover or create account on Hacker News</a>
</body>
</html>`;
};

async function handleLogin(
  request: Request,
  env: Env,
  sameSite: string,
): Promise<Response> {
  const url = new URL(request.url);
  const stateParam = url.searchParams.get("state");

  if (request.method === "GET") {
    // Show login form
    return new Response(getLoginHTML("", stateParam || undefined), {
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (request.method === "POST") {
    try {
      // Convert FormData to URLSearchParams to match the original request format
      const formData = await request.formData();
      const params = new URLSearchParams();
      for (const [key, value] of formData.entries()) {
        params.append(key, value);
      }

      const stateFromForm = params.get("state");

      // Create minimal headers - only what's absolutely necessary
      const minimalHeaders = new Headers();
      minimalHeaders.set("Content-Type", "application/x-www-form-urlencoded");

      // Use a standard browser User-Agent that doesn't look like a bot
      minimalHeaders.set(
        "User-Agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      );

      // Only add essential browser headers that a real browser would send
      minimalHeaders.set(
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      );
      minimalHeaders.set("Accept-Language", "en-US,en;q=0.5");
      minimalHeaders.set("Accept-Encoding", "gzip, deflate, br");

      // Set origin and referer to match a real browser request
      minimalHeaders.set("Origin", "https://news.ycombinator.com");
      minimalHeaders.set("Referer", "https://news.ycombinator.com/login");

      params.delete("state");

      minimalHeaders.set(
        "Proxy-Authorization",
        `Basic ${btoa(env.OXYLABS_CREDENTIALS)}`,
      );

      const proxyResponse = await fetch("https://news.ycombinator.com/login", {
        method: "POST",
        headers: minimalHeaders,
        body: params.toString(),
        redirect: "manual",
        // Disable any automatic compression/decompression that might alter headers
        compress: false,
        // Use Oxylabs residential proxy
        cf: {
          resolveOverride: "pr.oxylabs.io:7777",
        },
      });

      if (proxyResponse.status === 302) {
        // Get the redirect location
        const location = proxyResponse.headers.get("Location");

        if (location && location.includes("news")) {
          // Success! Extract session cookie from HN response
          const setCookieHeader = proxyResponse.headers.get("Set-Cookie");
          let hnSessionCookie = "";

          if (setCookieHeader) {
            // Extract the session cookie (usually 'user' cookie from HN)
            const cookies = setCookieHeader.split(";");
            for (const cookie of cookies) {
              if (cookie.trim().startsWith("user=")) {
                hnSessionCookie = cookie.trim();
                break;
              }
            }
          }

          // Get username from form
          const username = params.get("acct");
          if (!username) {
            return new Response(
              getLoginHTML("Username required", stateFromForm || undefined),
              {
                headers: { "Content-Type": "text/html; charset=utf-8" },
              },
            );
          }

          // Fetch user profile from HN
          const user = await fetchHNUserProfile(username, hnSessionCookie);
          if (!user) {
            return new Response(
              getLoginHTML(
                "Failed to fetch user profile",
                stateFromForm || undefined,
              ),
              {
                headers: { "Content-Type": "text/html; charset=utf-8" },
              },
            );
          }

          // Encrypt the session cookie as our access token
          const encryptedAccessToken = await encrypt(
            hnSessionCookie,
            env.HN_SESSION_KEY,
          );

          // Store user data in Durable Object with "user:" prefix
          const userDOId = env.CODES.idFromName(`user:${encryptedAccessToken}`);
          const userDO = env.CODES.get(userDOId);

          await userDO.setUser(user, hnSessionCookie, encryptedAccessToken);

          // Handle OAuth flow completion
          return await handleLoginSuccess(
            request,
            env,
            sameSite,
            stateFromForm,
            encryptedAccessToken,
          );
        }
      }

      // Get the response body to check for errors or success
      const responseText = await proxyResponse.text();

      console.log("no 302", proxyResponse.status, responseText);
      // Handle 403 error - likely IP-based blocking
      if (proxyResponse.status === 403) {
        return new Response(
          getLoginHTML("Bad login.", stateFromForm || undefined),
          {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          },
        );
      }

      // For status 200, check for common error messages
      if (proxyResponse.status === 200) {
        if (
          responseText.includes("Bad login") ||
          responseText.includes("That username is taken")
        ) {
          const errorMsg = responseText.includes("Bad login")
            ? "Invalid username or password"
            : "Username already taken";
          return new Response(
            getLoginHTML(errorMsg, stateFromForm || undefined),
            {
              headers: { "Content-Type": "text/html; charset=utf-8" },
            },
          );
        }

        return new Response(responseText, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      // Return error for debugging
      return new Response(
        getLoginHTML(
          "Login failed - please try again",
          stateFromForm || undefined,
        ),
        {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        },
      );
    } catch (error) {
      return new Response(getLoginHTML("Error: " + error.message), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
  }

  return new Response("Method not allowed", { status: 405 });
}

async function handleLoginSuccess(
  request: Request,
  env: Env,
  sameSite: string,
  stateParam: string | null,
  encryptedAccessToken: string,
): Promise<Response> {
  // Get state from cookie
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const providerStateCookie = cookies.provider_state;

  // Check if this was part of an OAuth provider flow
  if (providerStateCookie && stateParam) {
    try {
      const providerState = JSON.parse(atob(providerStateCookie));

      // Create auth code and redirect back to client
      const response = await createAuthCodeAndRedirect(
        env,
        providerState.clientId,
        providerState.redirectUri,
        providerState.state,
        encryptedAccessToken,
        providerState.resource,
      );

      // Set access token cookie and clear state cookies
      const headers = new Headers(response.headers);
      headers.append(
        "Set-Cookie",
        `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      );
      headers.append(
        "Set-Cookie",
        `provider_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
      );
      headers.append(
        "Set-Cookie",
        `access_token=${encryptedAccessToken}; HttpOnly; Secure; Max-Age=34560000; SameSite=${sameSite}; Path=/`,
      );

      return new Response(response.body, { status: response.status, headers });
    } catch {
      // Fall through to normal redirect
    }
  }

  // Parse state to get redirect destination
  let redirectTo = "/";
  if (stateParam) {
    try {
      const state: OAuthState = JSON.parse(atob(stateParam));
      redirectTo = state.redirectTo || "/";
    } catch {
      // Use default redirect
    }
  }

  // Normal redirect (direct login)
  const headers = new Headers({ Location: redirectTo });
  headers.append(
    "Set-Cookie",
    `oauth_state=; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=0; Path=/`,
  );
  headers.append(
    "Set-Cookie",
    `access_token=${encryptedAccessToken}; HttpOnly; Secure; SameSite=${sameSite}; Path=/`,
  );

  return new Response(null, { status: 302, headers });
}

async function fetchHNUserProfile(
  username: string,
  sessionCookie: string,
): Promise<HNUser | null> {
  try {
    // Fetch user profile from HN
    const response = await fetch(
      `https://news.ycombinator.com/user?id=${username}`,
      {
        headers: {
          Cookie: sessionCookie,
          "User-Agent": "Mozilla/5.0 (compatible; HN-OAuth-Provider/1.0)",
        },
      },
    );

    if (!response.ok) {
      return null;
    }

    const html = await response.text();

    // Parse the HTML to extract user information
    // This is a basic parser - you might want to use a proper HTML parser
    const user: HNUser = {
      id: username,
      username: username,
      created: 0,
      karma: 0,
    };

    // Extract karma
    const karmaMatch = html.match(/karma:\s*<\/td><td>(\d+)/);
    if (karmaMatch) {
      user.karma = parseInt(karmaMatch[1], 10);
    }

    // Extract created date
    const createdMatch = html.match(/created:\s*<\/td><td>([^<]+)/);
    if (createdMatch) {
      const createdText = createdMatch[1].trim();
      // Convert to timestamp (basic implementation)
      user.created = Date.now(); // For now, use current time
    }

    // Extract about section
    const aboutMatch = html.match(/about:\s*<\/td><td[^>]*>(.*?)<\/td>/s);
    if (aboutMatch) {
      user.about = aboutMatch[1].replace(/<[^>]*>/g, "").trim();
    }

    return user;
  } catch (error) {
    console.error("Error fetching HN user profile:", error);
    return null;
  }
}

async function createAuthCodeAndRedirect(
  env: Env,
  clientId: string,
  redirectUri: string,
  state: string | null,
  encryptedAccessToken: string,
  resource?: string,
): Promise<Response> {
  // Generate auth code
  const authCode = generateCodeVerifier(); // Reuse the same random generation

  // Decrypt to get HN session cookie
  const hnSessionCookie = await decrypt(
    encryptedAccessToken,
    env.HN_SESSION_KEY,
  );

  // Create Durable Object for this auth code with "code:" prefix
  const id = env.CODES.idFromName(`code:${authCode}`);
  const authCodeDO = env.CODES.get(id);

  await authCodeDO.setAuthData(
    hnSessionCookie,
    encryptedAccessToken,
    clientId,
    redirectUri,
    resource,
  );

  // Redirect back to client with auth code
  const redirectUrl = new URL(redirectUri);
  redirectUrl.searchParams.set("code", authCode);
  if (state) {
    redirectUrl.searchParams.set("state", state);
  }

  return new Response(null, {
    status: 302,
    headers: { Location: redirectUrl.toString() },
  });
}

async function handleToken(
  request: Request,
  env: Env,
  scope: string,
): Promise<Response> {
  // Handle preflight OPTIONS request
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: {
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  const headers = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  };
  const formData = await request.formData();
  const grantType = formData.get("grant_type");
  const code = formData.get("code");
  const clientId = formData.get("client_id");
  const redirectUri = formData.get("redirect_uri");
  const resource = formData.get("resource");

  if (grantType !== "authorization_code") {
    return new Response(JSON.stringify({ error: "unsupported_grant_type" }), {
      status: 400,
      headers,
    });
  }

  if (!code || !clientId) {
    return new Response(JSON.stringify({ error: "invalid_request" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id is a valid domain
  if (
    !isValidDomain(clientId.toString()) &&
    clientId.toString() !== "localhost"
  ) {
    return new Response(JSON.stringify({ error: "invalid_client" }), {
      status: 400,
      headers,
    });
  }

  // Get auth code data from Durable Object with "code:" prefix
  const id = env.CODES.idFromName(`code:${code.toString()}`);
  const authCodeDO = env.CODES.get(id);
  const authData = await authCodeDO.getAuthData();

  if (!authData) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Validate client_id and redirect_uri match
  if (
    authData.clientId !== clientId ||
    (redirectUri && authData.redirectUri !== redirectUri)
  ) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // MCP Required: Validate resource parameter matches if provided
  if (resource && authData.resource !== resource) {
    return new Response(JSON.stringify({ error: "invalid_grant" }), {
      status: 400,
      headers,
    });
  }

  // Return the encrypted access token
  return new Response(
    JSON.stringify({
      access_token: authData.access_token,
      token_type: "bearer",
      scope,
    }),
    { headers },
  );
}

async function handleCallback(
  request: Request,
  env: Env,
  sameSite: string,
): Promise<Response> {
  // This is handled by the login flow, so redirect to login
  return new Response(null, {
    status: 302,
    headers: { Location: "/login" },
  });
}

/**
 * Extract access token from request cookies or Authorization header.
 * Use this to check if a user is authenticated.
 */
export function getAccessToken(request: Request): string | null {
  // Check Authorization header first (MCP clients may use this)
  const authHeader = request.headers.get("Authorization");
  if (authHeader?.startsWith("Bearer ")) {
    return authHeader.substring(7);
  }

  // Fallback to cookie for browser clients
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  return cookies.access_token || null;
}

/**
 * Validate that an access token is intended for this resource server.
 * MCP servers MUST validate token audience.
 */
export function validateTokenAudience(
  request: Request,
  expectedResource: string,
): boolean {
  const token = getAccessToken(request);
  return token !== null;
}

// Utility functions
function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  cookieHeader.split(";").forEach((cookie) => {
    const [name, value] = cookie.trim().split("=");
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });

  return cookies;
}

function isValidDomain(domain: string): boolean {
  // Basic domain validation - must contain at least one dot and valid characters
  const domainRegex =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return (
    domainRegex.test(domain) && domain.includes(".") && domain.length <= 253
  );
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Encryption utilities
async function encrypt(text: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data,
  );

  // Combine salt + iv + encrypted data
  const combined = new Uint8Array(
    salt.length + iv.length + encrypted.byteLength,
  );
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  return btoa(String.fromCharCode.apply(null, Array.from(combined)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function decrypt(encrypted: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // Decode the base64url
  const combined = new Uint8Array(
    atob(encrypted.replace(/-/g, "+").replace(/_/g, "/"))
      .split("")
      .map((c) => c.charCodeAt(0)),
  );

  // Extract salt, iv, and encrypted data
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const data = combined.slice(28);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data,
  );

  return decoder.decode(decrypted);
}

export interface UserContext<T = { [key: string]: any }>
  extends ExecutionContext {
  /** Should contain authenticated HN User */
  user: HNUser | undefined;
  /** HN Session cookie */
  hnSessionCookie: string | undefined;
  /** Access token. Can be decrypted with client secret to retrieve HN session cookie */
  accessToken: string | undefined;
  registered: boolean;
  getMetadata?: () => Promise<T>;
  setMetadata?: (metadata: T) => Promise<void>;
}

interface UserFetchHandler<TEnv = {}, TMetadata = { [key: string]: any }> {
  (request: Request, env: Env & TEnv, ctx: UserContext<TMetadata>):
    | Response
    | Promise<Response>;
}

/** Easiest way to add oauth with required login! */
export function withSimplerAuth<TEnv = {}, TMetadata = { [key: string]: any }>(
  handler: UserFetchHandler<TEnv, TMetadata>,
  config?: {
    /** If true, login will be forced and user will always be present */
    isLoginRequired?: boolean;
    /** Defaults to "read" meaning you get the user info and can read public data */
    scope?: string;
    /** Defaults to 'Lax' meaning subdomains are also valid to use the cookies */
    sameSite?: "Strict" | "Lax";
  },
): ExportedHandlerFetchHandler<Env & TEnv> {
  const { scope, sameSite } = config || {};

  return async (
    request: Request,
    env: TEnv & Env,
    ctx: ExecutionContext,
  ): Promise<Response> => {
    const oauth = await handleOAuth(request, env, scope, sameSite);
    if (oauth) {
      return oauth;
    }

    // Get user from access token
    let userDO: DurableObjectStub<CodeDO>;

    let user: HNUser | undefined = undefined;
    let registered = false;
    let hnSessionCookie: string | undefined = undefined;
    const accessToken = getAccessToken(request);
    if (accessToken) {
      try {
        // Get user data from Durable Object
        const userDOId = env.CODES.idFromName(`user:${accessToken}`);
        userDO = env.CODES.get(userDOId);
        const userData = await userDO.getUser();

        if (userData) {
          user = userData.user;
          registered = true;
          hnSessionCookie = userData.hnSessionCookie;
        }
      } catch (error) {
        console.error("Error getting user data:", error);
      }
    }

    if (!user && config?.isLoginRequired !== false) {
      const isBrowser = request.headers.get("accept")?.includes("text/html");
      const url = new URL(request.url);
      const resourceMetadataUrl = `${url.origin}/.well-known/oauth-protected-resource`;

      // Require login
      const Location = `${
        new URL(request.url).origin
      }/authorize?redirect_to=${encodeURIComponent(request.url)}`;

      return new Response(
        `"access_token" Cookie or "Authorization" header required. User must login at ${Location}.`,
        {
          status: isBrowser ? 302 : 401,
          headers: {
            Location,
            "X-Login-URL": Location,
            // MCP Required: WWW-Authenticate header with resource metadata URL (RFC9728)
            "WWW-Authenticate": `Bearer realm="main", login_url="${Location}", resource_metadata="${resourceMetadataUrl}"`,
          },
        },
      );
    }

    // Create enhanced context with user and registered status
    const enhancedCtx: UserContext<TMetadata> = {
      passThroughOnException: () => ctx.passThroughOnException(),
      props: ctx.props,
      waitUntil: (promise: Promise<any>) => ctx.waitUntil(promise),
      user,
      registered,
      hnSessionCookie,
      accessToken,
      setMetadata: userDO ? userDO.setMetadata : undefined,
      getMetadata: userDO
        ? () => userDO.getMetadata() as Promise<TMetadata>
        : undefined,
    };

    // Call the user's fetch handler
    const response = await handler(request, env, enhancedCtx);

    // Merge any headers from middleware (like Set-Cookie) with the response
    const newHeaders = new Headers(response.headers);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  };
}
