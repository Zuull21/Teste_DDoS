from scapy.all import sniff, IP

class DDoSAnalyzer:
    def __init__(self):
        self.attack_count = 0
        self.attackers = set()

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Atualizar contadores
            self.attack_count += 1
            self.attackers.add(src_ip)

            # Exibir informações
            print(f"Packet from {src_ip} to {dst_ip}")

    def start_sniffing(self, interface, filter_rule):
        sniff(iface=interface, filter=filter_rule, prn=self.packet_callback, store=0)

# Substitua "enp0s3" pelo nome da sua interface de rede
interface = "enp0s3"

# Substitua "host 192.168.1.1" pelo seu próprio endereço IP ou pela máscara de rede desejada
filter_rule = "host 192.168.1.1"

# Criar instância do analisador
analyzer = DDoSAnalyzer()

# Iniciar a captura de pacotes
analyzer.start_sniffing(interface, filter_rule)

# Imprimir resultados
print(f"Total de pacotes recebidos: {analyzer.attack_count}")
print(f"IPs atacantes: {', '.join(analyzer.attackers)}")
