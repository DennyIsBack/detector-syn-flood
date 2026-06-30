import tkinter as tk
from tkinter import ttk

from gui.modais import (
    abrir_modal_grafico,
)

from controller.app_controller import AppController


class JanelaPrincipal:

    def __init__(self):

        self.janela = tk.Tk()
        self.janela.title("Monitor TCP")
        self.janela.geometry("1000x500")

        self.criar_componentes()

        self.controller = AppController(self)
        self.controller.iniciar()
        self.atualizar_estatisticas()

        self.janela.protocol(
            "WM_DELETE_WINDOW",
            self.fechar
        )

    def atualizar_estatisticas(self):

        dados = self.controller.obter_estatisticas()

        self.lbl_syn.config(
            text=f"SYN recebidos: {dados['syn']}"
        )

        self.lbl_ack.config(
            text=f"ACK recebidos: {dados['ack']}"
        )

        self.lbl_percentual.config(
            text=f"Taxa de SYN / SYN-ACK: {dados['percentual']:.2f}%"
        )

        p = dados["percentual"]

        if p <= 50:
            self.lbl_status.config(
                text="⚠ Possível SYN Flood detectado",
                fg="red"
            )

        elif p <= 85:
            self.lbl_status.config(
                text="⚠ Situação Anormal",
                fg="orange"
            )

        else:
            self.lbl_status.config(
                text="✔ Situação Normal",
                fg="green"
            )

        self.janela.after(
            1000,
            self.atualizar_estatisticas
        )

    def criar_componentes(self):

        frame_principal = tk.Frame(self.janela)
        frame_principal.pack(
            fill="both",
            expand=True
        )

        frame_esquerda = tk.Frame(
            frame_principal
        )

        frame_esquerda.pack(
            side="left",
            fill="both",
            expand=True
        )

        self.tabela = ttk.Treeview(
            frame_esquerda,
            columns=(
                "Flag",
                "Origem",
                "Destino"
            ),
            show="headings"
        )

        self.tabela.heading(
            "Flag",
            text="Flag TCP"
        )

        self.tabela.heading(
            "Origem",
            text="IP Origem"
        )

        self.tabela.heading(
            "Destino",
            text="IP Destino"
        )

        self.tabela.pack(
            fill="both",
            expand=True,
            padx=5,
            pady=5
        )

        frame_direita = tk.Frame(
            frame_principal,
            width=250,
            bg="#eaeaea"
        )

        frame_direita.pack(
            side="right",
            fill="y"
        )

        frame_direita.pack_propagate(False)

        tk.Button(
            frame_direita,
            text="Enviar SYN",
            command=lambda:
                self.controller.enviar_syn()
        ).pack(fill="x", padx=10, pady=10)

        tk.Button(
            frame_direita,
            text="Gráfico",
            command=lambda: abrir_modal_grafico(
                self.janela,
                self.controller
            )
        ).pack(fill="x", padx=10, pady=5)

        frame_stats = tk.LabelFrame(
            frame_direita,
            text="Estatísticas"
            )
        frame_stats.pack(
            fill="x",
            padx=10,
            pady=10
        )

        self.lbl_syn = tk.Label(frame_stats, text="SYN recebidos: 0", anchor="w")
        self.lbl_syn.pack(fill="x", padx=5, pady=2)

        self.lbl_ack = tk.Label(frame_stats, text="ACK recebidos: 0", anchor="w")
        self.lbl_ack.pack(fill="x", padx=5, pady=2)

        self.lbl_percentual = tk.Label(frame_stats, text="Taxa de SYN / SYN-ACK: 0%", anchor="w")
        self.lbl_percentual.pack(fill="x", padx=5, pady=2)

        self.lbl_status = tk.Label(
            frame_stats,
            text="",
            font=("Arial", 10, "bold")
        )
        self.lbl_status.pack(pady=10)

    def adicionar_tabela(
        self,
        flag,
        origem,
        destino
    ):

        def atualizar():

            self.tabela.insert(
                "",
                "end",
                values=(
                    flag,
                    origem,
                    destino
                )
            )

            self.tabela.yview_moveto(1)

        self.janela.after(
            0,
            atualizar
        )

    def fechar(self):

        self.controller.parar()
        self.janela.destroy()

    def executar(self):
        self.janela.mainloop()