import os
import platform
import time

def send_ping(ip_address, count=5000, duration=30):
    """
    Envia pings para um endereço IP específico por um determinado período.

    Parâmetros:
    - ip_address: Endereço IP de destino.
    - count: Número de pings a serem enviados.
    - duration: Duração em segundos para enviar os pings.
    """
    interval = duration / count
    if platform.system().lower() == "windows":
        command = f"ping -n {count} -i {interval} {ip_address}"
    else:
        command = f"ping -c {count} -i {interval} {ip_address}"

    os.system(command)

# Substitua "192.168.1.1" pelo IP de destino desejado
ip_destino = "131.72.61.69"

# Envie pings repetidamente para o IP de destino por 30 segundos
send_ping(ip_destino, count=5000, duration=30)

input("Pressione Enter para sair")

