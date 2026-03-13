/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // API requests go through nginx directly (location /api/ in nginx.conf)
  // No rewrites needed — they caused socket hang up on long LLM requests
};

module.exports = nextConfig;
