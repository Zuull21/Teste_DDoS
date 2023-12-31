import pymssql
from scapy.all import sniff, IP
from datetime import datetime, timedelta

# Conectar ao banco de dados
sql_server_cnx = pymssql.connect(
    server='18.204.118.27',
    database='SecureATM',
    user='sa',
    password='Secure2023'
)
cursor_sql_server = sql_server_cnx.cursor()

class TrafficAnalyzer:
    def __init__(self):
        self.ip_traffic = {}
        self.alert_threshold = 5000
        self.alerted_ips = set()
        self.running = True

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src

            if src_ip not in self.ip_traffic:
                self.ip_traffic[src_ip] = []

            timestamp = datetime.now()
            self.ip_traffic[src_ip].append(timestamp)

            # Verificar se atingiu o limiar de alerta
            if len(self.ip_traffic[src_ip]) >= self.alert_threshold and src_ip not in self.alerted_ips:
                self.alerted_ips.add(src_ip)
                self.stop_sniffing()
                self.insert_ddos_alert(src_ip, len(self.ip_traffic[src_ip]))
            else:
                self.insert_network_data(src_ip, timestamp)

    def insert_network_data(self, ip, timestamp):
        try:
            cursor_sql_server.execute("INSERT INTO rede (IP, data_hora, pacotesEnviados) VALUES (%s, %s, 1)", (ip, timestamp))
            sql_server_cnx.commit()

        except pymssql.Error as e:
            print(f"Erro ao inserir dados na tabela rede: {e}")

    def insert_ddos_alert(self, ip, packet_count):
        try:
            cursor_sql_server.execute("INSERT INTO DDoS (IPAtq, qtdPacotesAtq) VALUES (%s, %s)", (ip, packet_count))
            sql_server_cnx.commit()

        except pymssql.Error as e:
            print(f"Erro ao inserir dados na tabela DDoS: {e}")

    def start_sniffing(self, interface):
        print("Iniciando análise de tráfego...")
        sniff(iface=interface, prn=self.packet_callback, store=0, stop_filter=lambda x: not self.running)

    def stop_sniffing(self):
        print("Parando análise de tráfego...")
        self.running = False

        # Fechar a conexão com o banco de dados
        sql_server_cnx.close()

# Substitua "enp0s3" pelo nome da sua interface de rede
interface = "enp0s3"

# Criar instância do analisador de tráfego
analyzer = TrafficAnalyzer()

try:
    # Iniciar a captura de pacotes
    analyzer.start_sniffing(interface)

except KeyboardInterrupt:
    # Se o usuário pressionar Ctrl+C, interromper o script
    pass

