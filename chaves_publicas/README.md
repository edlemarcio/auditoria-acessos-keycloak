# Chaves públicas de assinatura dos pacotes

`chaves.json` lista as chaves Ed25519 que assinam os manifestos dos pacotes de evidência (formato em
[`docs/FORMATO_PACOTE.md`](../docs/FORMATO_PACOTE.md) §3.3), atuais e antigas. É publicado também num endereço
institucional e embutido no verificador (`verificador/kc_verificar/chaves/chaves.json`, mesma lista).

* Nova chave: `python -m auditor publicar-chave` (com o token do assinador), e depois um commit.
* Revogação: preencha `revogada_em` com a data, sem apagar a entrada. Pacotes carimbados antes da revogação continuam
  válidos.
* `uso` diz para que a chave vale. As chaves `local:` são do modo de desenvolvimento e não valem para produção; a
  lista de produção só tem chaves `vault:` do assinador de produção.
