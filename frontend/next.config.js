/** @type {import('next').NextConfig} */
const nextConfig = {
  // Showcase build: emit a fully static site to /frontend/out so it can be
  // hosted on any object storage / CDN with no backend at all.
  output: 'export',
  // Static exports cannot use the default next/image optimizer at runtime.
  images: { unoptimized: true },
  // Avoid relying on server-side trailing-slash redirects; emit deterministic
  // index.html files for every route.
  trailingSlash: true,
}
export default nextConfig
