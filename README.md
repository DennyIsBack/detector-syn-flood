# Detector de SYN Flood

Detector de ataques **SYN Flood** desenvolvido em **Python** com a biblioteca
**[Scapy](https://scapy.net/)**. A ferramenta captura o tráfego TCP em tempo real,
interpreta os cabeçalhos IP/TCP e identifica o padrão característico do ataque,
exibindo estatísticas e alertas em uma interface gráfica.

Repositório: https://github.com/DennyIsBack/detector-syn-flood

## Sobre o ataque

Em uma conexão TCP normal ocorre o *three-way handshake*: o cliente envia **SYN**,
o servidor responde com **SYN-ACK** e o cliente conclui com **ACK**. No **SYN Flood**,
o atacante envia muitos SYN com IPs falsificados (*spoofing*) e nunca envia o ACK
final. O servidor fica retransmitindo o SYN-ACK (com o RTO dobrando a cada tentativa —
*backoff exponencial*: 3s, 6s, 12s, 24s...), mantendo várias conexões **semiabertas** e
consumindo recursos.

## Lógica de detecção (ISH)

A detecção se baseia na assimetria entre os pacotes SYN e SYN-ACK, medida a cada
janela de 1 segundo:

```
ISH = ( Total de SYNs recebidos / Total de SYN-ACKs enviados ) * 100
```

- Em tráfego **normal**, cada SYN gera ~1 SYN-ACK, então o **ISH fica próximo de 100%**.
- Em um **ataque**, o servidor retransmite vários SYN-ACK por SYN, o denominador cresce
  e o **ISH cai bem abaixo de 100%**. Essa queda é o que dispara o alerta.

Limiares de status:

| Faixa de ISH        | Status               |
|---------------------|----------------------|
| ISH > 85%           | Situação Normal      |
| 50% < ISH <= 85%    | Situação Anormal     |
| ISH <= 50%          | Possível SYN Flood   |

Ao entrar em ataque, é registrado um alerta (nível WARNING) em `logs/syn_flood.log`
contendo o ISH, as contagens de SYN/SYN-ACK e o IP de origem com mais conexões
semiabertas.

## Estrutura de pastas

```
sniffer/      Captura de pacotes (AsyncSniffer) e interpretação dos cabeçalhos;
              gerador de tráfego de teste (sender.py)
detection/    Lógica de detecção (ISH, estatísticas por IP) e módulo de registro (logging)
gui/          Interface gráfica (Tkinter) com tabela, estatísticas e gráfico
controller/   Ligação entre a interface e o sniffer/detector
main.py       Ponto de entrada da aplicação
```

## Instalação

Requer **Python 3.12+**.

```bash
pip install -r requirements.txt
```

No **Windows** é necessário instalar o **[Npcap](https://npcap.com/)** (driver de
captura de pacotes).

## Como executar

A captura de pacotes exige privilégios de administrador. Abra o terminal
**como administrador** e execute, na raiz do projeto:

```bash
python main.py
```

A janela **"Monitor TCP"** exibe a tabela de pacotes capturados, o painel de
estatísticas (SYN, SYN-ACK, ISH, média/pico de SYNs e IPs suspeitos), o status de
segurança e um gráfico de tendência.

### Testando o detector

- **Enviar SYN**: envia um único pacote SYN (teste rápido de captura).
- **Simular ataque**: dispara um burst controlado (SYN de IPs falsificados da faixa
  de teste `203.0.113.0/24` + SYN-ACK simulando as retransmissões), fazendo o ISH cair
  e o alerta disparar. Use apenas em ambiente próprio e controlado.

## Autores

Jader Sauzem Volpato e João Vitor Lemos Reis — UCS, 2026.
