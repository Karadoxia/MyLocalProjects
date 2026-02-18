# Production Docker image for new-project
# Multi-stage: build (node) -> runtime (node:18-alpine)

FROM node:22-alpine AS builder
WORKDIR /app

# install build deps
COPY package*.json tsconfig.json ./
COPY frontend/package*.json frontend/ || true
RUN npm ci --omit=dev || true

# copy source and build
COPY . .
RUN npm run build:all

# Runtime image
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Create a non-root user
RUN addgroup -S app && adduser -S -G app app

# Copy only the runtime artifacts
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY package*.json ./

# Install production deps only
RUN npm ci --omit=dev --production || true

# Expose port used by server (default in start-bg/start script: 5002)
EXPOSE 5002

# Use non-root user
USER app

CMD ["node", "dist/index.js"]
