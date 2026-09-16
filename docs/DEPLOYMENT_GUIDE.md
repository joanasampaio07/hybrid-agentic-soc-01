# 🌐 Guia de Deploy e Publicação com Endereço Web Público (Com Autenticação e SSL)

Este guia ensina como colocar o **Hybrid Agentic SOC** em um endereço web público e seguro (`https://...`) para demonstrações comerciais e implantação em empresas clientes.

---

## 🔒 1. Segurança e Autenticação de Acesso

O sistema agora conta com **autenticação obrigatória por padrão**:
- **Página de Login**: `/static/login.html`
- **Usuário Padrão**: `admin`
- **Senha Padrão**: `admin123`
- **Como alterar as credenciais**:
  Defina no arquivo `.env` ou nas variáveis de ambiente da máquina:
  ```env
  ADMIN_USERNAME=seu_usuario_seguro
  ADMIN_PASSWORD=SuaSenhaForte2026!@#
  JWT_SECRET_KEY=sua_chave_secreta_super_forte_aleatoria
  ```

---

## 🚀 2. Como Colocar em um Endereço Web Público

### Opção A: **Cloudflare Tunnel (Mais Rápido, Gratuito e Seguro para Demos)**
*Ideal para demonstrar para clientes em reuniões ou gravar vídeos sem pagar servidor.*

1. Baixe o executável do Cloudflare Tunnel:
   - No Windows: `winget install --id Cloudflare.cloudflared` ou baixe em [developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
2. Execute o comando para criar uma URL pública instantânea com SSL:
   ```bash
   cloudflared tunnel --url http://localhost:8000
   ```
3. O Cloudflare gerará uma URL segura como:
   👉 `https://exemplo-aleatorio-soc.trycloudflare.com`
4. Você pode enviar esse link para qualquer pessoa acessar com a senha de admin!

---

### Opção B: **Deploy em VPS Cloud (AWS EC2, DigitalOcean, Hetzner, Linode)**
*Ideal para produção e contratos com empresas.*

1. **Suba uma instância Linux (Ubuntu 22.04 / 24.04)**:
   - Mínimo recomendado: 2 vCPUs e 4GB de RAM (ex: AWS `t3.medium` ou DigitalOcean `$24/mês`).
2. **Instale o Docker e Docker Compose**:
   ```bash
   curl -fsSL https://get.docker.com | sh
   sudo usermod -aG docker $USER
   ```
3. **Clone o seu repositório**:
   ```bash
   git clone https://github.com/joanasampaio07/hybrid-agentic-soc-01.git
   cd hybrid-agentic-soc-01
   ```
4. **Configure o `.env` com suas credenciais**:
   ```bash
   cp .env.example .env
   nano .env
   ```
5. **Suba o container com Docker Compose**:
   ```bash
   docker compose up -d
   ```
6. **Configure Domínio com Nginx e SSL Gratuito (Let's Encrypt)**:
   Instale o Nginx e Certbot:
   ```bash
   sudo apt update && sudo apt install nginx certbot python3-certbot-nginx -y
   ```
   Crie a configuração do Nginx em `/etc/nginx/sites-available/soc.seudominio.com.br`:
   ```nginx
   server {
       server_name soc.seudominio.com.br;

       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection "upgrade";
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```
   Ative e emita o certificado SSL:
   ```bash
   sudo ln -s /etc/nginx/sites-available/soc.seudominio.com.br /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl restart nginx
   sudo certbot --nginx -d soc.seudominio.com.br
   ```
7. Pronto! A sua plataforma estará acessível em **`https://soc.seudominio.com.br`** com HTTPS seguro, login e WebSockets em tempo real.

---

### Opção C: **Deploy em PaaS (Render / Railway / Fly.io)**

1. Conecte sua conta do GitHub no [Render.com](https://render.com) ou [Railway.app](https://railway.app).
2. Selecione o repositório `hybrid-agentic-soc-01`.
3. Escolha o deploy via `Dockerfile` (na pasta `backend`).
4. O serviço fornecerá um endereço público automático `https://hybrid-agentic-soc.onrender.com`.
