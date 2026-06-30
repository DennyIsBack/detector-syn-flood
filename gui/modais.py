import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure


def abrir_modal_grafico(parent, controller):

    modal = tk.Toplevel(parent)
    modal.title("Gráfico")
    modal.geometry("1000x650")

    fig = Figure(figsize=(9, 5))

    ax1 = fig.add_subplot(211)
    ax2 = fig.add_subplot(212)

    canvas = FigureCanvasTkAgg(fig, modal)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    def atualizar():

        historico = controller.obter_historico()

        tempo = [
            x["tempo"].strftime("%H:%M:%S")
            for x in historico
        ]

        percentual = [x["percentual"] for x in historico]
        syn = [x["syn"] for x in historico]
        ack = [x["ack"] for x in historico]

        ax1.clear()
        ax1.plot(percentual)
        ax1.set_ylim(0, 110)
        ax1.set_title("Diferença de SYN / SYN-ACK (%)")
        ax1.set_ylabel("%")

        ax2.clear()
        ax2.plot(syn, label="SYN")
        ax2.plot(ack, label="SYN-ACK")
        ax2.set_title("Pacotes por segundo")
        ax2.set_ylabel("Pacotes")
        ax2.legend()

        canvas.draw()

        modal.after(1000, atualizar)

    atualizar()