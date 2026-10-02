# Corpus local de capturas

Coloque capturas anonimizadas em `tests/fixtures/captures/` e execute:

```text
npm run verify:corpus
```

O diretório de capturas é ignorado pelo Git para evitar publicação acidental de endereços, nomes DNS ou payloads. A verificação compara contagem de quadros, hosts, domínios, SNI e distribuição de protocolos com o TShark. Use somente arquivos cuja coleta e retenção estejam autorizadas.
