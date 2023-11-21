#Simulador de ATK DDoS

import os
import platform

def send_ping(ip_address, count=4):
    """
    Envia pings para um endereço IP específico.

    Parâmetros:
    - ip_address: Endereço IP de destino.
    - count: Número de pings a serem enviados.
    """
    if platform.system().lower() == "windows":
        command = f"ping -n {count} {ip_address}"
    else:
        command = f"ping -c {count} {ip_address}"

    os.system(command)

# Substitua "192.168.1.1" pelo IP de destino desejado
ip_destino = "172.31.85.220"

# Envie pings repetidamente para o IP de destino
send_ping(ip_destino)
input("Pressione Enter para sair")
