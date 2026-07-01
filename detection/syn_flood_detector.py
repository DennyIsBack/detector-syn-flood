from collections import defaultdict
from collections import deque
from datetime import datetime

from detection.registro import get_logger


class SynFloodDetector:

    def __init__(self):

        #Limite de tempo em que uma porta fica aberta
        self.limite = 75

        # Logger para alertas e eventos em arquivo
        self.logger = get_logger()

        # Limiar de ISH abaixo do qual consideramos ataque
        self.limiar_ataque = 50

        # Estado atual (usado para detectar transicoes normal <-> ataque)
        self.em_ataque = False

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

            # ISH = (Total de SYNs recebidos / Total de SYN-ACKs enviados) * 100
            # Em trafego normal cada SYN gera ~1 SYN-ACK, entao ISH ~100%.
            # Em um ataque, o servidor retransmite varios SYN-ACK por SYN
            # (back off do RTO), o denominador cresce e o ISH cai bem abaixo
            # de 100% -- e essa queda que indica o SYN Flood.
            if ack == 0:
                percentual = 100
            else:
                percentual = (syn / ack) * 100

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

            self._verificar_alerta(percentual, syn, ack)

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

        

    def _ip_mais_suspeito(self):
        # Agrega as conexoes semiabertas (SYN sem handshake concluido) por
        # IP de origem e retorna o endereco com maior numero delas.
        contagem = defaultdict(int)

        for chave, dados in self.pacotes.items():
            if dados["syn"] == 1:
                ip_origem = chave[0]
                contagem[ip_origem] += 1

        if not contagem:
            return None

        return max(contagem, key=contagem.get)

    def _verificar_alerta(self, percentual, syn, ack):
        # Detecta a transicao de estado (normal <-> ataque) e registra em log.
        if percentual <= self.limiar_ataque and not self.em_ataque:
            self.em_ataque = True
            suspeito = self._ip_mais_suspeito() or "desconhecido"
            self.logger.warning(
                "ALERTA SYN Flood: ISH=%.1f%% | SYN=%d | SYN-ACK=%d | "
                "origem suspeita=%s",
                percentual, syn, ack, suspeito
            )

        elif percentual > self.limiar_ataque and self.em_ataque:
            self.em_ataque = False
            self.logger.info(
                "Situacao normalizada: ISH=%.1f%%", percentual
            )

    def obter_estatisticas(self):
        return self.estatisticas


    def obter_historico(self):
        return list(self.historico)