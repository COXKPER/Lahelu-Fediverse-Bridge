FROM node:22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache python3 make g++ git

COPY package*.json ./
RUN npm install --production

# ================= RUNTIME =================

FROM node:22-alpine

WORKDIR /app

RUN apk add --no-cache wget

COPY --from=builder /app/node_modules ./node_modules
COPY server.js ./

RUN mkdir -p /app/data

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]
