FROM node:20.11-alpine

RUN apk update && apk upgrade && apk add dumb-init
RUN addgroup -S web && adduser -S web

WORKDIR /app
COPY src/package*.json .

RUN npm i

COPY src .
RUN chown -R web:web .

USER web

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]