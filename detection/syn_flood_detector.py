from collections import defaultdict
from collections import deque
from datetime import datetime


class SynFloodDetector:

    def __init__(self):

        #Limite de tempo em que uma porta fica aberta
        self.limite = 75

        # estatísticas por IP
        self.pacotes = defaultdict(lambda: {
            "syn": 0,
            "ack": 0,
            "syn-ack": 0,
            "source_port": 0,
            "destiny_port": 0,
            "time_inicial": 0,
            "ultimo_time": 0
        })

        self.Syn_packages = 0
        self.SynAck_packages = 0
        self.stats_timer = None

        self.estatisticas = {
            "syn": 0,
            "ack": 0,
            "percentual": 100
        }

        self.historico = deque(maxlen=60) 

    def analisar(self, pkt):

        ip_origem = pkt["origem"]
        ip_destino = pkt["destino"]

        flag = pkt["flag"]

        source_port = pkt["source_port"]
        destiny_port = pkt["destiny_port"]

        timestamp = pkt["time"]

        chave_cliente = (ip_origem, ip_destino, source_port, destiny_port)
        
        chave_servidor = (ip_destino, ip_origem, destiny_port, source_port)

        if self.stats_timer is None:
            self.stats_timer = timestamp

        if timestamp - self.stats_timer >= 1:

            syn = self.Syn_packages
            ack = self.SynAck_packages

            if syn == 0:
                percentual = 100
            else:
                percentual = (ack / syn) * 100

            self.historico.append({
                "tempo": datetime.now(),
                "syn": syn,
                "ack": ack,
                "percentual": percentual
            })

            self.estatisticas = {
                "syn": syn,
                "ack": ack,
                "percentual": percentual
            }

            self.Syn_packages = 0
            self.SynAck_packages = 0

            self.stats_timer = timestamp

        #Se um cliente tentar fazer uma nova conexão
        if flag == "SYN" and chave_cliente not in self.pacotes:
            self.pacotes[chave_cliente]["syn"] = 1
            self.pacotes[chave_cliente]["source_port"] = source_port
            self.pacotes[chave_cliente]["destiny_port"] = destiny_port
            self.pacotes[chave_cliente]["time_inicial"] = timestamp
            self.pacotes[chave_cliente]["ultimo_time"] = timestamp
            self.Syn_packages += 1
            print("SYN =", chave_cliente)

        #Se o servidor responder o pedido de conexão
        elif flag == "SYN + ACK":
            self.pacotes[chave_servidor]["syn-ack"] += 1         
            self.pacotes[chave_servidor]["ultimo_time"] = timestamp
            self.SynAck_packages += 1
            print("SYN-ACK =", chave_servidor)

        #Se o cliente concluir o handshake
        elif flag == "ACK" and chave_cliente in self.pacotes:
            self.pacotes.pop(chave_cliente)

        #Verificar quais pacotes passaram do tempo limite de verificação
        for chave, dados in list(self.pacotes.items()):
            if timestamp - dados["ultimo_time"] > self.limite:
                self.pacotes.pop(chave)

        

    def obter_estatisticas(self):
        return self.estatisticas


    def obter_historico(self):
        return list(self.historico)