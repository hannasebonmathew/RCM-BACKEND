
FROM node:18-bookworm-slim

# Install Chromium and required dependencies
RUN apt-get update && apt-get install -y \
    chromium \
    ca-certificates \
    fonts-liberation \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Chromium executable location
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PUPPETEER_SKIP_DOWNLOAD=true

WORKDIR /app

# Install Node dependencies
COPY package*.json ./
RUN npm install

# Copy application
COPY . .

# Verify Chromium exists
RUN /usr/bin/chromium --version

EXPOSE 5000

CMD ["node", "server.js"]
