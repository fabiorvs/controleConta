FROM node:20-alpine

# Adicionar labels
LABEL maintainer="fabiorvs"
LABEL description="Controle Financeiro com Node.js e SQLite"

# Criar diretório da aplicação
WORKDIR /app

# Copiar package.json
COPY package*.json ./

# Instalar dependências (sql.js não precisa compilação)
RUN npm ci --only=production && \
    npm cache clean --force

# Copiar código da aplicação
COPY server.js ./
COPY public ./public

# Criar diretório para o banco de dados
RUN mkdir -p /app/data

# Criar usuário não-root
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

# Mudar para usuário não-root
USER nodejs

# Expor porta
EXPOSE 3000

# Variáveis de ambiente
ENV NODE_ENV=production \
    DATA_DIR=/app/data \
    PORT=3000

# Iniciar aplicação
CMD ["node", "server.js"]
