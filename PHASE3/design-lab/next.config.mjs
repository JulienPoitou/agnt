/** @type {import('next').NextConfig} */
const nextConfig = {
  reactCompiler: true,
  allowedDevOrigins: ["*.e2b.app"],
  compiler: { removeConsole: process.env.NODE_ENV === "production" },
};
export default nextConfig;
