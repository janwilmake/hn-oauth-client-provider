import {
  getAccessToken,
  handleOAuth,
  Env,
  CodeDO,
  HNUser,
} from "./hn-oauth-client-provider";

export { CodeDO };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle OAuth routes first
    const oauthResponse = await handleOAuth(request, env);
    if (oauthResponse) {
      return oauthResponse;
    }

    const url = new URL(request.url);

    if (url.pathname === "/") {
      return handleHome(request, env);
    }

    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;

async function handleHome(request: Request, env: Env): Promise<Response> {
  const accessToken = getAccessToken(request);
  if (!accessToken) {
    return new Response(
      `
      <html>
        <body>
          <h1>HackerNews OAuth Demo</h1>
          <p>You are not logged in.</p>
          <a href="/authorize">Login with HackerNews (direct flow)</a><br>
          <a href="/provider">Try provider flow example</a>
        </body>
      </html>
    `,
      { headers: { "Content-Type": "text/html" } },
    );
  }

  const userDOId = env.CODES.idFromName(`user:${accessToken}`);
  const userDO = env.CODES.get(userDOId);
  const userData = await userDO.getUser();
  if (!userData) {
    return new Response(
      `
      <html>
        <body>
          <h1>HackerNews OAuth Demo</h1>
          <p>Error fetching user info</p>
          <a href="/logout">Logout</a>
        </body>
      </html>
      `,
      {
        headers: { "Content-Type": "text/html" },
      },
    );
  }
  const { user } = userData;

  return new Response(
    `
    <html>
      <body>
        <h1>HackerNews OAuth Demo</h1>
        <p>Welcome, ${user.username}!</p>
        <p>Karma: ${user.karma}</p>
        <p>Created: ${user.created ? new Date(user.created).toLocaleDateString() : 'Unknown'}</p>
        ${user.about ? `<p>About: ${user.about}</p>` : ''}
        <a href="/logout">Logout</a><br>
        <a href="/provider">Try provider flow example</a>
      </body>
    </html>
  `,
    {
      headers: { "Content-Type": "text/html" },
    },
  );
}