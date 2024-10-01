FROM node:21-alpine AS build
WORKDIR /app

COPY . .
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm
RUN pnpm install --frozen-lockfile
RUN pnpm run build

FROM node:21-alpine
WORKDIR /app

COPY --from=build /app/build/ /app/package.json /app/pnpm-lock.yaml ./
RUN npm install -g pnpm
RUN pnpm install --frozen-lockfile --prod

ENTRYPOINT ["/usr/local/bin/node", "index.js"]
CMD []
