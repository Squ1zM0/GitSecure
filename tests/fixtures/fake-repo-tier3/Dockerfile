# Fake-repo fixture for Tier 3 infra tests. Placeholder values only —
# no real images, hosts, or credentials.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:latest
WORKDIR /app
COPY --from=build /app/dist ./dist
ARG API_TOKEN
USER root
ADD https://example.com/releases/fake-app.tar.gz /tmp/fake-app.tar.gz
CMD ["node", "dist/index.js"]
