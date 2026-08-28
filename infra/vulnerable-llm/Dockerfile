# A deliberately vulnerable target. Never deploy this anywhere reachable.
FROM node:22-alpine
WORKDIR /app
COPY server.mjs ./
USER node
EXPOSE 8090
CMD ["node", "server.mjs"]
