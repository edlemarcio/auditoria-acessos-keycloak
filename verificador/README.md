# kc-verificar

O kc-verificar confere pacotes de evidência do kc-auditor no formato 2, sem banco e sem rede. Ele é independente do
auditor: não importa nada de `auditor/` e reimplementa a partir da especificação pública
([`docs/FORMATO_PACOTE.md`](../docs/FORMATO_PACOTE.md)) os hashes, a árvore Merkle, a validação do carimbo do tempo
e as regras de cálculo. Um perito da outra parte pode usá-lo, ou reimplementá-lo, para conferir o pacote.

## Instalação

São três dependências (`cryptography`, `rfc8785` e `asn1crypto`), fixadas por versão e por hash:

```bash
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.lock
pip install --no-deps .
```

A instalação baixa do PyPI. A verificação não usa rede.

## Uso

```bash
kc-verificar investigacao_14_v1.zip                    # assinatura, carimbo, hashes, folhas, fatias, trilha, âncoras
kc-verificar investigacao_14_v1.zip --recalcular       # refaz KPIs, consolidado, destaques e cobertura e compara
kc-verificar investigacao_14_v1.zip --revelacao r.json # um evento revelado depois pertence ao conjunto assinado?
kc-verificar investigacao_14_v1.zip --json             # resultado em JSON
```

A primeira linha da saída resume o resultado. Por exemplo: "Pacote íntegro, assinado pela chave
vault:kc-auditor-assinatura:v1, carimbado em 27/11/2026 14:02 (UTC)." Depois vem cada conferência, marcada como
`[ok]`, `[aviso]` ou `[FALHA]`. O código de saída é 0 para pacote íntegro, 1 para pacote com falha e 2 para erro de
uso.

## Em que o verificador confia

* **Chaves de assinatura.** O verificador aceita só as chaves publicadas em `kc_verificar/chaves/chaves.json`, cópia
  versionada de `chaves_publicas/chaves.json`. `--chaves` acrescenta outra lista no mesmo formato, e uma chave enviada
  dentro do pacote nunca é aceita.
* **Raízes do carimbo do tempo.** As AC-Raiz da ICP-Brasil ficam em `kc_verificar/raizes/icp-brasil/`. A raiz da ACT
  de homologação fica em `raizes/homologacao/` e só vale com `--homologacao`.
* **Revogação.** O verificador usa as LCRs que vieram no pacote (`lcr/`) e informa até que data a revogação foi
  conferida.

## O que ele confere

1. Zip seguro: limite de 2 GB e de 10 mil arquivos, nomes sem `..`, taxa de compressão limitada (proteção contra zip
   bomb).
2. `manifesto.json` em JSON canônico, assinatura Ed25519 por chave publicada e carimbo RFC 3161 (§8 da
   especificação).
3. SHA-256 de cada arquivo declarado. Arquivo a mais ou a menos é falha.
4. Folhas → raízes de fatia → raiz da investigação. Contas excluídas aparecem com decisão registrada.
5. No pacote sem máscara, cada evento original recalcula a sua folha com o seu sal.
6. Compromissos das requisições → raiz.
7. Trilha encadeada e selo de cada fatia na trilha.
8. Âncoras diárias: prova de inclusão da cabeça da cadeia e carimbo de cada dia.
9. Relatório técnico em PDF/A-2b gerado do `resultados.json` do pacote.
10. Com `--recalcular`: KPIs, consolidado por janela, destaques e cobertura, comparados com `resultados.json`, os CSVs
    e a planilha.
