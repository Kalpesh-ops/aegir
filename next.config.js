/** @type {import('next').NextConfig} */
const nextConfig = {
  // Every route in this showcase is fully prerenderable (SSG). On Vercel,
  // Next.js will emit them as static HTML at the edge automatically — no
  // `output: 'export'` required, and using the default .next build output
  // keeps the Vercel Next.js adapter happy (it expects routes-manifest.json
  // under .next/, which static exports do not produce).
  trailingSlash: true,
  images: { unoptimized: true },
}
export default nextConfig
