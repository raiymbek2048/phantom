const { createServer } = require("http");
const { parse } = require("url");
const next = require("next");

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const server = createServer((req, res) => {
    const parsedUrl = parse(req.url, true);
    handle(req, res, parsedUrl);
  });

  // Increase timeouts for long API proxy calls (LLM validation etc.)
  server.timeout = 300000; // 5 minutes
  server.keepAliveTimeout = 300000;
  server.headersTimeout = 310000;

  server.listen(3000, "0.0.0.0", () => {
    console.log("> PHANTOM Frontend ready on http://0.0.0.0:3000");
  });
});
