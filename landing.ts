import { CodeDO, withSimplerAuth } from "./hn-oauth-client-provider";
export { CodeDO };

// Simple markdown parser with syntax highlighting support
function parseMarkdown(markdown: string): string {
  let html = markdown;

  // Extract and temporarily replace code blocks to prevent them from being processed by other rules
  const codeBlocks: string[] = [];
  html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (match, lang, code) => {
    const placeholder = `__CODE_BLOCK_${codeBlocks.length}__`;
    const escapedCode = escapeHtml(code.trim());
    const langClass = lang ? ` class="language-${lang}"` : "";
    codeBlocks.push(`<pre><code${langClass}>${escapedCode}</code></pre>`);
    return placeholder;
  });

  // Inline code (must come before other processing)
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

  // Headers
  html = html.replace(/^### (.*$)/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.*$)/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.*$)/gm, "<h1>$1</h1>");

  // Bold and italic
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");

  // Links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');

  // Lists
  html = html.replace(/^\* (.+$)/gm, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>)/s, "<ul>$1</ul>");
  html = html.replace(/<\/li>\s*<ul>/g, "</li>");
  html = html.replace(/<\/ul>\s*<li>/g, "<li>");

  // Numbered lists
  html = html.replace(/^\d+\. (.+$)/gm, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>)/s, (match) => {
    if (!match.includes("<ul>")) {
      return `<ol>${match}</ol>`;
    }
    return match;
  });

  // Paragraphs (must come after other block elements)
  html = html.replace(/^([^<\n].+$)/gm, "<p>$1</p>");

  // Clean up extra newlines and spaces
  html = html.replace(/\n\s*\n/g, "\n");

  // Restore code blocks
  codeBlocks.forEach((block, index) => {
    html = html.replace(`__CODE_BLOCK_${index}__`, block);
  });

  return html;
}

function escapeHtml(text: string): string {
  const div = new Array();
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export default {
  fetch: withSimplerAuth(
    async (request, env, ctx) => {
      const url = new URL(request.url);

      if (url.pathname === "/blog") {
        try {
          // Fetch the blog.md file from assets
          const blogResponse = await env.ASSETS.fetch(
            new URL("/blog.md", request.url),
          );

          if (!blogResponse.ok) {
            throw new Error("Blog post not found");
          }

          const markdownContent = await blogResponse.text();
          const htmlContent = parseMarkdown(markdownContent);

          const blogHtml = `<!DOCTYPE html>
<html lang="en">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Building a HackerNews OAuth Provider from First Principles</title>
<meta name="description" content="How a weekend hack evolved into a production-ready OAuth provider (but then I got blocked)" />
<meta name="robots" content="index, follow" />

<!-- Facebook Meta Tags -->
<meta property="og:url" content="https://https://hn.simplerauth.com/blog" />
<meta property="og:type" content="website" />
<meta property="og:title" content="Building a HackerNews OAuth Provider from First Principles" />
<meta property="og:description" content="How a weekend hack evolved into a production-ready OAuth provider (but then I got blocked)" />
<meta property="og:image" content="https://quickog.com/screenshot/https://hn.simplerauth.com/blog" />
<meta property="og:image:alt" content="How a weekend hack evolved into a production-ready OAuth provider (but then I got blocked)"/>
<meta property="og:image:width" content="1200"/>
<meta property="og:image:height" content="630"/>

<!-- Twitter Meta Tags -->
<meta name="twitter:card" content="summary_large_image" />
<meta property="twitter:domain" content="https://hn.simplerauth.com/blog" />
<meta property="twitter:url" content="https://https://hn.simplerauth.com/blog" />
<meta name="twitter:title" content="Building a HackerNews OAuth Provider from First Principles" />
<meta name="twitter:description" content="How a weekend hack evolved into a production-ready OAuth provider (but then I got blocked)" />
<meta name="twitter:image" content="https://quickog.com/screenshot/https://hn.simplerauth.com/blog" />
<link rel="stylesheet" href="styles.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/typescript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/html.min.js"></script>

<body>
    <header>
        <h1><a href="/" style="color: inherit; text-decoration: none;">simpler auth</a></h1>
        <p>oauth templates for cloudflare workers</p>
    </header>

    <main class="blog-content">
        ${htmlContent}
    </main>

    <footer>
        <p>built by <a href="https://x.com/janwilmake">janwilmake</a> because auth doesn't need to be complicated</p>
        <p><a href="/">← back to home</a></p>
    </footer>

    <script>
        document.addEventListener('DOMContentLoaded', (event) => {
            hljs.highlightAll();
        });
    </script>
</body>
</html>`;

          return new Response(blogHtml, {
            headers: { "Content-Type": "text/html" },
          });
        } catch (error) {
          return new Response(
            `<html><body><h1>Error</h1><p>Could not load blog post: ${error.message}</p><a href="/">← back to home</a></body></html>`,
            {
              status: 500,
              headers: { "Content-Type": "text/html" },
            },
          );
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
          { headers: { "Content-type": "text/html" } },
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
    },
    { isLoginRequired: false },
  ),
};
