from scapy.all import sniff
from collections import defaultdict
import time

# Dicionário para rastrear as conexões ativas
conexoes_ativas = defaultdict(int)

# Limite inicial de pacotes por segundo para identificar tráfego anormal
limite_inicial = 100

# Fator de crescimento do limite
fator_crescimento = 1.2

# Tempo de observação em segundos
tempo_de_observacao = 60

# Inicie a captura de pacotes na interface de rede.
def packet_callback(packet):
    global limite_pacotes_por_segundo, conexoes_ativas
    pacotes_recebidos = time.time()
    
    # Remove conexões inativas
    conexoes_ativas = {ip: last_seen for ip, last_seen in conexoes_ativas.items() if pacotes_recebidos - last_seen <= tempo_de_observacao}
    
    # Verifica o endereço IP de origem do pacote
    ip_origem = packet[0][1].src
    conexoes_ativas[ip_origem] = pacotes_recebidos

    # Calcula o número de conexões ativas
    num_conexoes_ativas = len(conexoes_ativas)
    
    # Calcula o limite de pacotes por segundo com base no número de conexões ativas
    limite_pacotes_por_segundo = int(limite_inicial * (fator_crescimento ** num_conexoes_ativas))
    
# Inicie a captura de pacotes na interface de rede.
sniff(iface='Intel(R) Wireless-AC 9462', prn=packet_callback)

# Verifique se o tráfego excede o limite definido.
if num_conexoes_ativas > limite_pacotes_por_segundo:
    print("Ataque DDoS detectado! Tráfego anormal.")