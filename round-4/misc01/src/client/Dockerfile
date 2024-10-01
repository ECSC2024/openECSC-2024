FROM node:20-alpine

WORKDIR /app

COPY package.json package.json
RUN npm install

COPY . .

ENV URL=ws://localhost:5000/toggle
CMD ["node", "index.js"]