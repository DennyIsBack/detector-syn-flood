import threading

from sniffer.sniffer import SnifferTCP
from sniffer.sender import enviar_syn, simular_ataque


class AppController:

    def __init__(self, view):

        self.view = view

        self.sniffer = SnifferTCP(
            self.view.adicionar_tabela
        )

    def obter_estatisticas(self):
        return self.sniffer.detector.obter_estatisticas()

    def iniciar(self):
        self.sniffer.iniciar()

    def parar(self):
        self.sniffer.parar()

    def enviar_syn(self):
        enviar_syn()

    def simular_ataque(self):
        # Roda em uma thread para nao congelar a interface durante o burst.
        threading.Thread(target=simular_ataque, daemon=True).start()

    def obter_historico(self):
        return self.sniffer.detector.obter_historico()