# Build stage
FROM node:18-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# Production image
FROM node:18-alpine AS prod
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production --no-audit --no-fund
COPY --from=build /app/dist ./dist
EXPOSE 4001
ENV NODE_ENV=production
CMD ["node","dist/index.js"]
