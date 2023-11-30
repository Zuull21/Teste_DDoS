from scapy.all import sniff, IP
from datetime import datetime, timedelta
import threading
import time

class TrafficAnalyzer:
    def __init__(self):
        self.ip_traffic = {}  # Dicionário para armazenar o tráfego por IP
        self.alert_threshold = 1.5  # 50% acima da média
        self.running = True  # Variável para controlar a execução do script
        self.trafego_normal = 0  # Variável para indicar tráfego normal
        self.alteracoes_identificadas = 0  # Variável para indicar alterações no tráfego

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Atualizar o tráfego por IP
            self.ip_traffic[src_ip] = self.ip_traffic.get(src_ip, 0) + 1

    def calculate_traffic_stats(self):
        # Calcular a média de pacotes por minuto para cada IP
        current_time = datetime.now()
        minute_ago = current_time - timedelta(minutes=1)

        for ip, count_time in list(self.ip_traffic.items()):
            if count_time < minute_ago:
                del self.ip_traffic[ip]
            else:
                self.ip_traffic[ip] = sum(1 for t in count_time if t >= minute_ago)

    def check_for_alerts(self):
        # Verificar se há alertas com base na média por minuto
        alerts = []
        for ip, count in self.ip_traffic.items():
            average = count / 1  # 1 minuto para simplificar
            if count > 0 and self.ip_traffic[ip] > self.alert_threshold * average:
                alerts.append(ip)

        return alerts

    def start_sniffing(self, interface):
        print("Iniciando análise de tráfego...")
        sniff(iface=interface, prn=self.packet_callback, store=0)
        print("Análise de tráfego encerrada.")

    def stop_sniffing(self):
        print("Parando análise de tráfego...")
        self.running = False

# Substitua "enp0s3" pelo nome da sua interface de rede
interface = "enp0s3"

# Criar instância do analisador de tráfego
analyzer = TrafficAnalyzer()

# Iniciar a captura de pacotes em uma thread separada
sniff_thread = threading.Thread(target=analyzer.start_sniffing, args=(interface,))
sniff_thread.start()

try:
    while analyzer.running:
        # Executar verificações e imprimir mensagens
        analyzer.calculate_traffic_stats()
        alerts = analyzer.check_for_alerts()

        if not alerts:
            analyzer.trafego_normal = 1
            analyzer.alteracoes_identificadas = 0
            print("Tráfego normal.")
        else:
            analyzer.trafego_normal = 0
            analyzer.alteracoes_identificadas = 1
            print(f"Alterações no tráfego identificadas. IPs com tráfego elevado: {', '.join(alerts)}")

        # Aguardar antes de realizar a próxima verificação
        time.sleep(60)

except KeyboardInterrupt:
    # Se o usuário pressionar Ctrl+C, interromper o script
    pass

finally:
    # Parar a captura de pacotes e esperar que a thread termine
    analyzer.stop_sniffing()
    sniff_thread.join()
