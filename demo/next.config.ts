import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Embedder-Policy', value: 'require-corp' },
        ],
      },
    ]
  },
  serverExternalPackages: ['squid-js'],
  webpack(config, { isServer }) {
    if (!isServer) {
      config.experiments = { ...config.experiments, asyncWebAssembly: true }
      config.module.rules.push({ test: /\.wasm$/, type: 'asset/resource' })
    }
    return config
  },
}

export default nextConfig
