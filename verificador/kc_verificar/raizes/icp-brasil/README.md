# AC-Raiz da ICP-Brasil

Coloque aqui, em PEM ou DER (`.pem`/`.crt`), os certificados das AC-Raiz da ICP-Brasil vigentes (v5 em diante),
obtidos do repositório oficial do ITI, e confira a impressão digital SHA-256 de cada um contra a publicada pelo ITI
antes de versionar. São as únicas raízes que o verificador aceita para o carimbo do tempo de produção.

Enquanto a ACT credenciada não está contratada, os pacotes de homologação são carimbados pela ACT de teste
(`infra/act_homologacao.py`), cuja raiz fica em `../homologacao/` e só é aceita com `kc-verificar --homologacao`.
