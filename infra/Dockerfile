# Attestor platform image.
#
# One image, three entrypoints: the console API, the portal API and the worker. They differ only in
# the command, which keeps the build simple and means all three run the same code.
#
# TypeScript is not compiled. Node 22 strips types natively, so the source runs as written and there
# is no build output to drift from the repository.

FROM node:22-alpine AS base
ENV PNPM_HOME=/pnpm
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable || npm install -g pnpm@10
WORKDIR /app

# ---------------------------------------------------------------------------------------------
FROM base AS dependencies

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY apps/api/package.json apps/api/
COPY apps/console/package.json apps/console/
COPY apps/website/package.json apps/website/
COPY packages/core/package.json packages/core/
COPY packages/findings/package.json packages/findings/
COPY packages/policy/package.json packages/policy/
COPY packages/report/package.json packages/report/
COPY packages/scanners/package.json packages/scanners/
COPY packages/shared/package.json packages/shared/

RUN pnpm install --frozen-lockfile --prod=false

# ---------------------------------------------------------------------------------------------
FROM base AS runtime

# Playwright's Chromium, for the PDF pipeline. The alpine build needs the system browser rather
# than the downloaded one.
RUN apk add --no-cache chromium nss freetype harfbuzz ca-certificates ttf-freefont tini
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser

COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies /app/apps ./apps
COPY --from=dependencies /app/packages ./packages
COPY package.json pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/api ./apps/api
COPY packages ./packages
COPY infra/migrations ./infra/migrations
COPY infra/tool-images.lock.json* ./infra/

# Runs as the node user. The worker needs the Docker socket, which is granted by the compose file
# rather than by running this container as root.
RUN mkdir -p /tmp/attestor && chown -R node:node /tmp/attestor /app
USER node

ENV NODE_ENV=production
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--experimental-strip-types", "apps/api/src/server.ts"]

# ---------------------------------------------------------------------------------------------
FROM base AS console

# The surface is baked in at build time, not chosen at runtime: next.config.ts inlines it, and a
# single image that could be either would be one environment variable away from serving the staff
# console to a client. Build twice, deploy twice.
ARG ATTESTOR_SURFACE=console
ENV ATTESTOR_SURFACE=$ATTESTOR_SURFACE

COPY --from=dependencies /app/node_modules ./node_modules
COPY . .
# The API URL is read at request time by the server, but next build needs one present.
ENV ATTESTOR_API_URL=http://api:8080
ENV ATTESTOR_PORTAL_API_URL=http://portal-api:8081
RUN pnpm --filter @attestor/console build

USER node
ENV NODE_ENV=production
EXPOSE 3000
CMD ["pnpm", "--filter", "@attestor/console", "start"]
