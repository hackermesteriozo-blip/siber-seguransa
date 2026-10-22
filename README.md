# ANON CYBERSEC PRO — Login e cadastro

## Arquivos
- `index.html`: frontend estático para GitHub Pages.
- `server.py`: API FastAPI com cadastro, login e perfil autenticado.
- `requirements.txt`: dependências Python.
- `render.yaml`: blueprint para publicar API e PostgreSQL no Render.
- `.env.example`: exemplo de configuração local.

## Teste local
Requer Python 3.10+.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Kali/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python server.py
```

Para testar o frontend e backend juntos localmente, abra `http://127.0.0.1:8000`.
O frontend está configurado para usar a API online; para desenvolvimento local, troque `API_BASE` em `index.html` para `http://127.0.0.1:8000`.

## Publicação online
1. Envie `server.py`, `requirements.txt` e `render.yaml` para o repositório GitHub.
2. No Render, crie um Blueprint a partir desse repositório e revise os recursos que serão criados. O blueprint cria um serviço web e um banco PostgreSQL.
3. Depois que a API for publicada, copie a URL HTTPS real do serviço.
4. Em `index.html`, substitua `https://COLOQUE-A-URL-DO-SEU-BACKEND.onrender.com` pelo endereço real da API.
5. Publique `index.html` no repositório do GitHub Pages.
6. Confirme que `CORS_ORIGINS` no Render contém a origem exata do seu Pages, sem barra final, por exemplo `https://SEU-USUARIO.github.io`. Se o site estiver em um domínio próprio, use esse domínio.
7. Teste `/api/health`, cadastro, saída e login.

## Segurança e limitações
- O JWT é mantido em `sessionStorage`: ele é removido ao fechar a sessão do navegador, mas scripts maliciosos executados na página ainda podem acessá-lo. Mantenha dependências atualizadas e não adicione scripts desconhecidos.
- O backend armazena senhas com Argon2 via `pwdlib`; senhas em texto puro nunca são gravadas.
- `render.yaml` pede ao Render para gerar `JWT_SECRET`. Não substitua por um segredo publicado no repositório.
- Para produção pública, adicione limitação de tentativas, verificação de e-mail, recuperação de senha, monitoramento e política de privacidade. Não use esta base como sistema crítico sem revisão de segurança.
- Planos gratuitos e a disponibilidade de banco persistente variam. Verifique limites e política de suspensão do provedor antes de depender dele.
- O frontend atual é um portal de autenticação inicial; ainda não conecta ferramentas de auditoria ao usuário nem oferece permissões administrativas.
