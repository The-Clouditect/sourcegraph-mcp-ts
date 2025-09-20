FROM node:lts-alpine

WORKDIR /app

# Copy only what's needed for build
COPY package.json tsconfig.json ./
COPY src ./src

# Install and build
RUN npm install && npm run build

EXPOSE 3003

CMD ["npm", "run", "start:streamable"]