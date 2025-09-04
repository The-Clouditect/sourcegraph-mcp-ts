FROM node:lts-alpine

WORKDIR /app

# Copy only what's needed for build
COPY package.json tsconfig.json ./
COPY src ./src

# Install and build
RUN npm install && npm run build

EXPOSE 3001

CMD ["npm", "run", "start:mcp"]