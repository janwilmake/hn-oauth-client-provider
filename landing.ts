import { CodeDO, withSimplerAuth } from "./hn-oauth-client-provider";
export { CodeDO };

// Simple markdown parser
function parseMarkdown(markdown) {
  let html = markdown;

  // Escape HTML to prevent rendering
  html = html
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Code blocks with syntax highlighting (```lang blocks)
  html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (match, lang, code) => {
    return `<pre><code class="language-${
      lang || "plain"
    }">${code.trim()}</code></pre>`;
  });

  // Inline code
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

  // Headers
  html = html.replace(/^### (.*$)/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.*$)/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.*$)/gm, "<h1>$1</h1>");

  // Bold and italic
  html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.*?)\*/g, "<em>$1</em>");

  // Links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

  // Lists
  html = html.replace(/^\* (.*$)/gm, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>)/s, "<ul>$1</ul>");

  // Paragraphs
  html = html.replace(/\n\n/g, "</p><p>");
  html = "<p>" + html + "</p>";

  // Clean up empty paragraphs
  html = html.replace(/<p><\/p>/g, "");
  html = html.replace(/<p>(<h[1-6]>)/g, "$1");
  html = html.replace(/(<\/h[1-6]>)<\/p>/g, "$1");
  html = html.replace(/<p>(<ul>)/g, "$1");
  html = html.replace(/(<\/ul>)<\/p>/g, "$1");
  html = html.replace(/<p>(<pre>)/g, "$1");
  html = html.replace(/(<\/pre>)<\/p>/g, "$1");

  return html;
}

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      const url = new URL(request.url);

      if (url.pathname === "/blog") {
        try {
          // Fetch blog content from assets
          const blogResponse = await env.ASSETS.fetch(
            new Request(`${url.origin}/blog.md`),
          );

          if (!blogResponse.ok) {
            return new Response("Blog not found", { status: 404 });
          }

          const blogMarkdown = await blogResponse.text();
          const blogHtml = parseMarkdown(blogMarkdown);

          return new Response(
            `
<!DOCTYPE html>
<html lang="en">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>blog - simpler auth</title>
<style>
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.6;
  color: #333;
  max-width: 800px;
  margin: 0 auto;
  padding: 20px;
  background: #fafafa;
}

header {
  text-align: center;
  margin-bottom: 40px;
  padding-bottom: 20px;
  border-bottom: 2px solid #eee;
}

header h1 {
  font-size: 2.5em;
  margin-bottom: 10px;
  color: #2c3e50;
}

header p {
  font-size: 1.1em;
  color: #666;
  margin: 10px 0;
}

header a {
  display: inline-block;
  padding: 12px 24px;
  background: #3498db;
  color: white;
  text-decoration: none;
  border-radius: 6px;
  margin-top: 15px;
  transition: background 0.3s;
}

header a:hover {
  background: #2980b9;
}

main {
  background: white;
  padding: 30px;
  border-radius: 8px;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

h1, h2, h3 {
  color: #2c3e50;
  margin-top: 30px;
  margin-bottom: 15px;
}

h1 { font-size: 2em; }
h2 { font-size: 1.5em; }
h3 { font-size: 1.3em; }

p {
  margin-bottom: 15px;
  text-align: justify;
}

ul {
  margin: 15px 0;
  padding-left: 20px;
}

li {
  margin-bottom: 8px;
}

pre {
  background: #2d3748;
  color: #e2e8f0;
  padding: 20px;
  border-radius: 8px;
  overflow-x: auto;
  margin: 20px 0;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 14px;
  line-height: 1.5;
}

code {
  background: #f7fafc;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 0.9em;
  color: #d63384;
}

pre code {
  background: none;
  padding: 0;
  color: inherit;
  border-radius: 0;
}

/* Syntax highlighting */
.language-javascript code,
.language-js code {
  color: #e2e8f0;
}

.language-html code {
  color: #81c784;
}

.language-css code {
  color: #64b5f6;
}

.language-json code {
  color: #ffb74d;
}

a {
  color: #3498db;
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}

blockquote {
  border-left: 4px solid #3498db;
  margin: 20px 0;
  padding: 10px 20px;
  background: #f8f9fa;
  font-style: italic;
}

footer {
  text-align: center;
  margin-top: 40px;
  padding: 20px;
  color: #666;
  border-top: 1px solid #eee;
}

footer a {
  color: #3498db;
  font-weight: 500;
}
</style>

<body>
    <header>
        <h1>simpler auth</h1>
        <p>oauth templates for cloudflare workers</p>
        <a href="/">← back to home</a>
    </header>

    <main>
        ${blogHtml}
    </main>

    <footer>
        <p>built by <a href="https://x.com/janwilmake">janwilmake</a> because auth doesn't need to be complicated</p>
    </footer>
</body>
</html>`,
            {
              headers: { "Content-Type": "text/html;charset=utf8" },
            },
          );
        } catch (error) {
          return new Response("Error loading blog", { status: 500 });
        }
      }

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

      if (!ctx.registered) {
        return new Response(
          `<html><body><h1>HackerNews OAuth Demo</h1>
          <p><a href="/login">login</a></p>

           <p><a href="/blog">read blog</a></p>

           <p><a href="https://github.com/janwilmake/hn-oauth-client-provider">check the repo</a></p>
          </body></html>`,
          { headers: { "Content-Type": "text/html" } },
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
        <a href="/api/user">View raw user data (JSON)</a><br>
        <a href="/blog">Read blog</a>
      </body></html>`,
        { headers: { "Content-Type": "text/html;charset=utf8" } },
      );
    },
    { isLoginRequired: false },
  ),
};
