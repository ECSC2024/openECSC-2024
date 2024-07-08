# Node docker file with latest version and chromium
FROM node:22.2.0-alpine3.20

# Install dependencies
RUN apk update && apk add --no-cache chromium procps

# Set the working directory and add user non root
WORKDIR /home/app
RUN addgroup -S app && adduser -S app -G app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the files
COPY ./src .

# Expose the port
EXPOSE 3000
RUN chown -R app /home/app
USER app
# Start the app
CMD ["node", "app.js"]
