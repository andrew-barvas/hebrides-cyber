FROM node:18-bookworm-slim

# --- System dependencies ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    nmap \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# --- sqlmap (Python) ---
RUN pip3 install --break-system-packages sqlmap

# --- Nuclei (Go binary, pinned) ---
ARG NUCLEI_VERSION=v3.3.9
RUN curl -fsSL \
    "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# --- Nuclei templates (pre-download so first scan isn't slow) ---
RUN nuclei -update-templates -silent || true

# --- App ---
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ts-node for running TypeScript worker directly
RUN npm install --no-save ts-node

COPY tsconfig.json ./
COPY src/lib ./src/lib
COPY src/worker ./src/worker

ENV NODE_ENV=production

CMD ["node", "--require", "ts-node/register/transpile-only", "src/worker/index.ts"]
