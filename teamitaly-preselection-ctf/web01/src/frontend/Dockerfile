FROM node:21-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM node:21-alpine
WORKDIR /app

COPY --from=build /app/build/ /app/package.json /app/package-lock.json ./
RUN npm ci --omit dev

# Setup low privileged user
RUN addgroup -S web && adduser -S web -G web
USER web

ENTRYPOINT ["/usr/local/bin/node", "index.js"]
CMD []
