# ❌ Intentionally insecure Dockerfile for demo
FROM node:18

# ❌ Secret in ENV
ENV DB_PASSWORD=SuperSecret123
ENV API_KEY=sk-live-abc123def456

# ❌ Using ADD instead of COPY
ADD . /app

WORKDIR /app

RUN apt-get update && apt-get install -y curl wget

# ❌ Exposing sensitive ports
EXPOSE 3000 22 3306

RUN npm install

# ❌ No USER instruction (runs as root)
# ❌ No HEALTHCHECK

CMD ["node", "app.js"]
