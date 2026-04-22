# Linux-only glibc napi build for `squid-js` (e.g. `squid.linux-x64-gnu.node` for Vercel / linux/amd64).
# Darwin: run `pnpm run build` in this package on your Mac; this image cannot produce macOS .node files.
#
# Build context: monorepo root (so Cargo.toml, crates/, packages/, pnpm-lock.yaml are available).
# On Apple Silicon, force amd64 to match a typical Vercel Node (x86_64 glibc) runtime, from monorepo root:
#   docker build --platform=linux/amd64 -f packages/squid-js/build-linux-napi.Dockerfile -t squid-linux:local .
# Baked build + copy napi/ into this package (runs docker build, then copies napi/ out; see scripts/build-linux-napi.sh):
#   pnpm --filter squid-js run build:squid:linux
#   (from packages/squid-js: pnpm run build:squid:linux)
#
# Mount workflow (from monorepo root; rewrites the tree under /squid):
#   docker run --rm -v "$PWD":/squid -w /squid squid-linux:local \
#     bash -c 'pnpm install --no-frozen-lockfile && pnpm run build:squid-js'
#
# The image is built on Debian bookworm, Node 20, Rust nightly (see /squid/rust-toolchain.toml for wasm), wasm-pack, pnpm@9.12.0.
# Use `docker build --platform=linux/amd64` (do not hardcode platform in FROM; BuildKit warns on constant FromPlatform).

FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Rust (nightly + wasm32 per rust-toolchain.toml; native .node target matches the build platform, e.g. linux/amd64 when using --platform=linux/amd64)
ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN rustup default nightly && rustup target add wasm32-unknown-unknown

# wasm-pack (uses cargo from the active nightly toolchain)
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

RUN corepack enable && corepack prepare pnpm@9.12.0 --activate

WORKDIR /squid
COPY . .

# --no-frozen-lockfile: after version bumps, package.json can change before pnpm-lock.yaml; frozen would fail the image build.
RUN pnpm install --no-frozen-lockfile && pnpm run build:squid-js
