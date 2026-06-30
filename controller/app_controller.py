from sniffer.sniffer import SnifferTCP
from sniffer.sender import enviar_syn


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

    def obter_historico(self):
        return self.sniffer.detector.obter_historico()