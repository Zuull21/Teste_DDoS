from scapy.all import sniff, IP
from datetime import datetime, timedelta

class DDoSAnalyzer:
    def __init__(self):
        self.attack_count = 0
        self.attackers = {}  # Usamos um dicionário para armazenar o contador por IP
        self.threshold = 5000  # Número mínimo de pacotes para considerar como ataque
        self.time_window = 60  # Janela de tempo em segundos para contar os pacotes

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Atualizar contadores
            self.attack_count += 1
            self.attackers[src_ip] = datetime.now()  # Armazenar timestamp

            # Limpar contadores para IPs que não enviaram pacotes recentemente
            self.clean_counters()

            # Exibir informações em tempo real
            print(f"Packet from {src_ip} to {dst_ip}")

            if src_ip in self.attackers and (datetime.now() - self.attackers[src_ip]).total_seconds() <= self.time_window:
                print(f"Possible DDoS attack detected from {src_ip}! ({self.attackers[src_ip]} packets in {self.time_window} seconds)")

    def clean_counters(self):
        # Limpar contadores para IPs que não enviaram pacotes recentemente
        current_time = datetime.now()
        self.attackers = {ip: count_time for ip, count_time in self.attackers.items() if (current_time - count_time).total_seconds() <= self.time_window}

    def start_sniffing(self, interface, filter_rule):
        sniff(iface=interface, filter=filter_rule, prn=self.packet_callback, store=0)

    def get_attackers(self):
        return [ip for ip, count_time in self.attackers.items() if (datetime.now() - count_time).total_seconds() <= self.time_window]

# Substitua "enp0s3" pelo nome da sua interface de rede
interface = "enp0s3"

# Substitua "host 192.168.1.1" pelo seu próprio endereço IP ou pela máscara de rede desejada
filter_rule = "host 131.72.61.69"

# Criar instância do analisador
analyzer = DDoSAnalyzer()

# Iniciar a captura de pacotes
analyzer.start_sniffing(interface, filter_rule)

# Obter resultados
attackers = analyzer.get_attackers()
total_packets = analyzer.attack_count

# Imprimir resultados
print(f"Total de pacotes recebidos: {total_packets}")
print(f"IPs atacantes (mais de {analyzer.threshold} pacotes em {analyzer.time_window} segundos): {', '.join(attackers)}")

