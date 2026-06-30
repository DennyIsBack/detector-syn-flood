from scapy.all import IP, TCP, send


def enviar_syn():
    pacote = (
        IP(dst="8.8.8.8")
        / TCP(
            dport=80,
            sport=12345,
            flags="S"
        )
    )

    send(pacote, verbose=False)