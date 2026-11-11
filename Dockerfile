FROM node:18-bookworm-slim

WORKDIR /app

# Install Node dependencies
COPY package*.json ./
RUN npm install --production

# Copy application source
COPY . .

EXPOSE 5000

CMD ["node", "server.js"]