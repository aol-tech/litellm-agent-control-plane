# LAP na AOL Tech

Fork de LiteLLM-Labs/litellm-agent-control-plane para testar "agentes funcionários" no Slack da AOL Tech,
em paralelo ao hermes-lab.

## Subir / parar
```bash
docker compose -f compose.yaml -f compose.aol.yaml up -d postgres lap tunnel
docker compose -f compose.yaml -f compose.aol.yaml stop
```
- Local: http://localhost:4300 · Público: https://lap.aoltech.co (túnel Cloudflare `lap`, conta AOL Tech)
- Login: master key em `.env` (`LITELLM_MASTER_KEY`). Não é o `sk-local` padrão.
- Rede: só `aol-net` (o Docker Desktop está sem pool para redes novas). Aliases: `lap-web`, `lap-postgres`.

## Modelos
O LAP fala o formato Anthropic `/v1/messages`. `config.yaml` (local, não versionado) manda `haiku-5.5`,
`gpt-6-luna` e `gemini-3.8-flash` para o LiteLLM do aol-ops (`http://litellm:4000`) com a virtual key `lap`
(US$3/30d; ver `aol-ops/bin/keys`). Custo e traces aparecem no LiteLLM e no Langfuse do aol-ops.

## Arquivos locais (não versionados)
- `.env`: `LITELLM_MASTER_KEY`, `AOL_LITELLM_KEY`
- `config.yaml`: rotas de modelo (modelo em `aol/config.example.yaml`)
- `aol/tunnel/credentials.json`: credencial do túnel (recriar com `cloudflared tunnel token`/`create`)
