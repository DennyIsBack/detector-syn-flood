from scapy.all import AsyncSniffer, IP, TCP
from detection.syn_flood_detector import SynFloodDetector


class SnifferTCP:

    def __init__(self, callback):
        self.callback = callback
        self.detector = SynFloodDetector()

        self.sniffer = AsyncSniffer(
            prn=self.analisar_pacote,
            store=False
        )

    def traduzir_flags(self, flags):

        mapa = {
            "S": "SYN",
            "A": "ACK",
            "F": "FIN",
            "R": "RST",
            "P": "PSH",
            "U": "URG",
            "E": "ECE",
            "C": "CWR"
        }

        resultado = []

        for letra in str(flags):
            if letra in mapa:
                resultado.append(mapa[letra])

        return " + ".join(resultado)

    def analisar_pacote(self, pkt):

        if IP in pkt and TCP in pkt:

            origem = pkt[IP].src
            destino = pkt[IP].dst

            source_port = pkt[TCP].sport
            destiny_port = pkt[TCP].dport

            flag = self.traduzir_flags(pkt[TCP].flags)

            pacote_info = {
                "flag": flag,
                "origem": origem,
                "destino": destino,
                "source_port": source_port,
                "destiny_port": destiny_port,
                "time": pkt.time
            }

            self.detector.analisar(pacote_info)

            self.callback(
                flag,
                origem,
                destino
            )

    def iniciar(self):
        self.sniffer.start()

    def parar(self):

        try:
            if self.sniffer.running:
                self.sniffer.stop()
        except Exception as erro:
            print("Erro ao parar sniffer:", erro)

