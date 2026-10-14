# Controle VIP — Betas & Similar

Site estático (GitHub Pages) para controlar a entrega do VIP mensal.

- Abas **Betas** e **Similar**, com ID do Discord e e-mail de cada membro.
- Botão **Copiar** (ID, `<@id>` ou e-mail) → confirma **OK, entregue** para marcar o mês.
- Editar, adicionar e excluir membros pelo próprio site.
- Os dados ficam em `data.enc.json`, **criptografados** (AES-GCM + PBKDF2). Sem a senha ninguém lê.
- Edições salvam na hora no navegador; **Salvar no GitHub** grava no repositório
  (precisa de um fine-grained token com *Contents: Read and write* só neste repo).
