from scapy.all import sniff, IP
from datetime import datetime, timedelta
import threading
import time

class DDoSAnalyzer:
    def __init__(self):
        self.attack_count = 0
        self.all_attackers = set()
        self.highlighted_attackers = set()
        self.threshold = 5000
        self.time_window = 60
        self.sniffing_thread = None
        self.running = False

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            self.attack_count += 1
            self.all_attackers.add(src_ip)

            self.clean_counters()

            print(f"Packet from {src_ip} to {dst_ip}")

            if src_ip in self.all_attackers and (datetime.now() - self.all_attackers[src_ip]).total_seconds() <= self.time_window:
                print(f"Possible DDoS attack detected from {src_ip}! ({self.all_attackers[src_ip]} packets in {self.time_window} seconds)")
                if self.all_attackers[src_ip] >= self.threshold:
                    self.highlighted_attackers.add(src_ip)

    def clean_counters(self):
        current_time = datetime.now()
        self.all_attackers = {ip: count_time for ip, count_time in self.all_attackers.items() if (current_time - count_time).total_seconds() <= self.time_window}

    def start_sniffing(self, interface, filter_rule):
        self.running = True
        while self.running:
            sniff(iface=interface, filter=filter_rule, prn=self.packet_callback, store=0, timeout=60)

    def stop_sniffing(self):
        self.running = False
        if self.sniffing_thread:
            self.sniffing_thread.join()

    def start_dynamic_sniffing(self, interface, filter_rule):
        self.sniffing_thread = threading.Thread(target=self.start_sniffing, args=(interface, filter_rule))
        self.sniffing_thread.start()

        # Agendar a parada após 1 minuto e reiniciar o monitoramento
        threading.Timer(60, self.restart_sniffing, args=(interface, filter_rule)).start()

    def restart_sniffing(self, interface, filter_rule):
        self.stop_sniffing()
        self.attack_count = 0
        self.all_attackers = set()
        self.highlighted_attackers = set()
        self.start_dynamic_sniffing(interface, filter_rule)

    def get_all_attackers(self):
        return list(self.all_attackers)

    def get_highlighted_attackers(self):
        return list(self.highlighted_attackers)

# Substitua "enp0s3" pelo nome da sua interface de rede
interface = "enp0s3"

# Substitua "host 192.168.1.1" pelo seu próprio endereço IP ou pela máscara de rede desejada
filter_rule = "host 131.72.61.69"

# Criar instância do analisador
analyzer = DDoSAnalyzer()

# Iniciar a captura de pacotes dinamicamente
analyzer.start_dynamic_sniffing(interface, filter_rule)

# Aguardar até que a thread termine (isso ocorrerá após 1 minuto)
time.sleep(61)

# Obter resultados
all_attackers = analyzer.get_all_attackers()
highlighted_attackers = analyzer.get_highlighted_attackers()
total_packets = analyzer.attack_count

# Imprimir resultados
print(f"Total de pacotes recebidos: {total_packets}")
print(f"Todos os IPs atacantes: {', '.join(all_attackers)}")
print(f"IPs destacados (mais de {analyzer.threshold} pacotes em {analyzer.time_window} segundos): {', '.join(highlighted_attackers)}")
