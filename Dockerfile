FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY circuits ./circuits
RUN npm run build && npm prune --omit=dev
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "dist/index.js"]
