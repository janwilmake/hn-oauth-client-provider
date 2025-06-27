// This works in localhost, unfortunately, cloudflare ip is blocked, so it returns "Sorry" there instead with a 403, if we login with incorrect credentials, or try to register.
// however, with correct credentials, it still works! we get forwarded and a session token.

export { CodeDO } from "./hn-oauth-client-provider";

const getLoginHTML = (errorMessage = "") => {
  const errorHtml = errorMessage
    ? `<div style="margin-bottom: 20px;">${errorMessage}</div>`
    : "";

  return `<html lang="en">
<head>
    <meta name="referrer" content="origin">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="y18.svg">
</head>
<body>
    ${errorHtml}
    <b>Login</b>
    <br>
    <br>
    <form action="/login" method="post">
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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "GET") {
      return new Response(getLoginHTML(), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (request.method === "POST" && url.pathname === "/login") {
      try {
        // Convert FormData to URLSearchParams to match the original request format
        const formData = await request.formData();
        const params = new URLSearchParams();
        for (const [key, value] of formData.entries()) {
          params.append(key, value);
        }

        console.log("Form data:", [...params.entries()]);

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

        // Add proxy authorization header for Oxylabs
        minimalHeaders.set(
          "Proxy-Authorization",
          `Basic ${btoa(env.OXYLABS_CREDENTIALS)}`,
        );

        const proxyResponse = await fetch(
          "https://news.ycombinator.com/login",
          {
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
          },
        );

        console.log("Response status:", proxyResponse.status);
        console.log("Response headers:", [...proxyResponse.headers.entries()]);

        if (proxyResponse.status === 302) {
          // Get the redirect location
          const location = proxyResponse.headers.get("Location");
          console.log("Redirect location:", location);

          if (location && location.includes("news")) {
            return new Response(
              `Login credentials correct - would redirect to: ${location}`,
              {
                headers: { "Content-Type": "text/plain" },
              },
            );
          }
        }

        // Get the response body to check for errors or success
        const responseText = await proxyResponse.text();
        console.log("Response body preview:", responseText.substring(0, 200));

        // Handle 403 error - likely IP-based blocking
        if (proxyResponse.status === 403) {
          const errorMessage = `Bad login.`;
          console.log(proxyResponse.status, responseText);
          return new Response(getLoginHTML(errorMessage), {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          });
        }

        // For status 200, return the HTML response directly
        if (proxyResponse.status === 200) {
          return new Response(responseText, {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          });
        }

        // Handle common error cases
        if (responseText.includes("Bad login")) {
          return new Response(responseText, {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          });
        }

        // Return the full response for debugging
        return new Response(
          `Login - Status: ${
            proxyResponse.status
          }\n\nHeaders:\n${JSON.stringify(
            [...proxyResponse.headers.entries()],
            null,
            2,
          )}\n\nBody:\n${responseText}`,
          {
            headers: { "Content-Type": "text/plain" },
          },
        );
      } catch (error) {
        return new Response("Error: " + error.message, {
          status: 500,
          headers: { "Content-Type": "text/plain" },
        });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
