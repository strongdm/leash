// Silence Turbopack workspace-root warning by pinning root to this app dir.
const nextConfig = {
  output: "export",
  images: {
    unoptimized: true,
  },
  turbopack: {
    root: __dirname,
  },
};

export default nextConfig;
