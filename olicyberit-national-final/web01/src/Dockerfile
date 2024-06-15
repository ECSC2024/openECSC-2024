FROM node:22-alpine

WORKDIR /app/web
COPY web/package.json ./package.json
COPY web/package-lock.json ./package-lock.json
RUN npm ci

COPY web .
EXPOSE 3000

CMD ["node", "/app/web/index.js"]
