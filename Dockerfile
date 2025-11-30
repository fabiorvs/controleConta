# Use a versão mais recente e estável do Node.js
FROM node:23-alpine

# Adicionar labels para melhor manutenção
LABEL maintainer="fabiorvs"
LABEL description="Controle Financeiro com Node.js e SQLite"

# Instalar dependências necessárias para better-sqlite3
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    && rm -rf /var/cache/apk/*

# Criar usuário não-root para segurança
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Criar diretório da aplicação
WORKDIR /app

# Copiar arquivos de dependências como root primeiro
COPY package*.json ./

# Instalar dependências como root (necessário para compilar better-sqlite3)
RUN npm ci --only=production && \
    npm cache clean --force

# Copiar código da aplicação
COPY server.js ./
COPY public ./public

# Criar diretório para o banco de dados e ajustar permissões
RUN mkdir -p /app/data && \
    chown -R nodejs:nodejs /app

# Mudar para usuário não-root
USER nodejs

# Expor porta
EXPOSE 3000

# Variáveis de ambiente
ENV NODE_ENV=production \
    DATA_DIR=/app/data \
    PORT=3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Iniciar aplicação
CMD ["node", "server.js"]
