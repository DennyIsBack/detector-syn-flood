import random

from scapy.all import IP, TCP, conf, send


def enviar_syn():
    # Envia um unico SYN (util para um teste rapido de captura).
    pacote = (
        IP(dst="8.8.8.8")
        / TCP(
            dport=80,
            sport=12345,
            flags="S"
        )
    )

    send(pacote, verbose=False)


def _ip_local():
    # Descobre o IP local usado para sair para a rede (a "vitima" do teste).
    try:
        return conf.route.route("0.0.0.0")[1]
    except Exception:
        return "127.0.0.1"


def simular_ataque(quantidade=200, retransmissoes=3):
    # Gera um burst que reproduz o padrao de um SYN Flood em ambiente
    # controlado: para cada SYN de um IP falsificado (faixa de teste
    # 203.0.113.0/24, RFC 5737), injeta varios SYN-ACK "retransmitidos"
    # pela vitima (simulando o backoff exponencial do RTO). Isso derruba o
    # ISH (SYN / SYN-ACK) e dispara o alerta do detector.
    vitima = _ip_local()

    pacotes = []

    for _ in range(quantidade):
        origem = "203.0.113.%d" % random.randint(1, 254)
        porta = random.randint(1024, 65535)

        # SYN do atacante -> vitima
        pacotes.append(
            IP(src=origem, dst=vitima)
            / TCP(sport=porta, dport=80, flags="S")
        )

        # SYN-ACK retransmitidos pela vitima -> atacante
        for _ in range(retransmissoes):
            pacotes.append(
                IP(src=vitima, dst=origem)
                / TCP(sport=80, dport=porta, flags="SA")
            )

    send(pacotes, verbose=False)
