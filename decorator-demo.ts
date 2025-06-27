import { CodeDO, withSimplerAuth } from "./hn-oauth-client-provider";
export { CodeDO };

export default {
  fetch: withSimplerAuth(async (request, env, ctx) => {
    const url = new URL(request.url);

    if (url.pathname === "/api/user") {
      // API endpoint that returns user info as JSON
      return new Response(
        JSON.stringify({
          user: ctx.user,
          authenticated: ctx.registered,
        }),
        {
          headers: { "Content-Type": "application/json" },
        },
      );
    }

    return new Response(
      `<html><body>
        <h1>HackerNews OAuth Demo</h1>
        <p>Welcome, ${ctx.user?.username}!</p>
        <p>Karma: ${ctx.user?.karma || 0}</p>
        <p>Created: ${
          ctx.user?.created
            ? new Date(ctx.user.created).toLocaleDateString()
            : "Unknown"
        }</p>
        ${ctx.user?.about ? `<p>About: ${ctx.user.about}</p>` : ""}
        <a href="/logout">Logout</a><br>
        <a href="/provider">Try provider flow example</a><br>
        <a href="/api/user">View raw user data (JSON)</a>
      </body></html>`,
      { headers: { "Content-Type": "text/html;charset=utf8" } },
    );
  }),
};
