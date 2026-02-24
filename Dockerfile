FROM node:lts-alpine

WORKDIR /app

# Copy only what's needed for build
COPY package.json tsconfig.json ./
COPY src ./src

# Install and build
RUN NODE_OPTIONS=--max-old-space-size=8192 npm install && npx tsc --diagnostics

EXPOSE 3003

CMD ["npm", "run", "start:streamable"]