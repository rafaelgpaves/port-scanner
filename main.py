import subprocess
import socket
from termcolor import colored
import scapy.all as scapy
import ipaddress

#result = subprocess.run(["ifconfig"], capture_output=True)
#print(result.stdout.decode("UTF-8"))

KNOWN_PORTS = {
    7: "Echo",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "BOOTP",
    68: "BOOTP",
    69: "TFTP",
    80: "HTTP",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft EPMAP",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    153: "SGMP",
    156: "SQL",
    158: "DMSP",
    161: "SNMP",
    162: "SNMPTRAP",
    194: "IRC",
    199: "SMUX",
    201: "AppleTalk Routing Maintenance",
    213: "IPX",
    218: "MPP",
    220: "IMAPv3",
    259: "ESRO",
    264: "BGMP",
    280: "http-mgmt",
    369: "Rpc2portmap",
    370: "codaauth2",
    383: "HP data alarm manager",
    387: "AURP",
    401: "UPS",
    427: "SLP",
    443: "HTTPS",
    445: "Microsoft-DS (Directory Services)",
    3306: "MYSQL",
    3389: "RDP",
    5432: "PostreSQL"
}

class Scanner:
    def __init__(self):
        self.running = True

        self.IP = None
        self.networkIP = None
        self.mascaraSubRede = None
        self.IPv6 = None

        self.achou_banner = False

        self.portas_abertas = []
        self.portas_fechadas = []

    def scan(self, min_port: int, max_port: int, ipv6: bool, tipo = socket.SOCK_STREAM, protocolo = None):
        if min_port < 0 or min_port > 65355 or max_port < 0 or max_port > 65355:
            print("Insira dois números entre 0 e 65355\n")
            return

        # print(socket.gethostbyaddr(self.IP))
        # print("A")
        # print(socket.gethostbyname(self.wiki))
        # print("B")
        # print(socket.gethostname())

        self.portas_abertas = []

        # print(self.IP)
        # print(socket.gethostbyname(self.IP))
        # print(ipv6)

        # result = subprocess.run(["nmap", "-sV", "192.168.128.41"], capture_output=True)
        # for port in range(min_port, max_port+1):
        #     result = subprocess.run(["nmap", "-sV", "-p", str(port), "192.168.128.41"], capture_output=True)
        #     print(result.stdout.decode("UTF-8"))

        # result = subprocess.run(["nmap", "-O", "192.168.128.41"], capture_output=True)
        # print(result.stdout.decode("UTF-8"))

        for port in range(min_port, max_port+1):
            if ipv6:
                if protocolo:
                    client = socket.socket(socket.AF_INET6, tipo, protocolo)
                    client.settimeout(3)
                    r = client.connect_ex((self.IPv6, port))
                else:
                    client = socket.socket(socket.AF_INET6, tipo)
                    client.settimeout(3)
                    r = client.connect_ex((self.IPv6, port))
            else:
                if protocolo:
                    client = socket.socket(socket.AF_INET, tipo, protocolo)
                    client.settimeout(3)
                    r = client.connect_ex((self.IP, port))
                else:
                    client = socket.socket(socket.AF_INET, tipo)
                    client.settimeout(3)
                    r = client.connect_ex((self.IP, port))
            if r == 0:
                if self.portas_fechadas:
                    print(colored(f"Porta(s) {self.portas_fechadas[0]}-{self.portas_fechadas[-1]} está(ão) fechada(s)", "red"))
                servico = KNOWN_PORTS.get(port)
                if servico is None:
                    servico = "Serviço desconhecido"
                print(colored(f"Porta aberta: {port}, {servico}", "green"))
                self.portas_abertas.append(port)
                self.portas_fechadas = []
            else:
                if r == 111 or r == 11: # Porta esta fechada
                    self.portas_fechadas.append(port)
                else:
                    print(f"Porta {port} está filtrada")
            client.close()

    def scan_ports(self, min_port: int, max_port: int, host = None, network_scanner = False, UDP = False):
        try:
            min_port = int(min_port)
            max_port = int(max_port)
            if network_scanner and host:
                self.scan(min_port, max_port, False, host)
                return

            print("\nEscolha IPv4 ou IPV6: ")
            print("1. IPv4")
            print("2. IPv6")
            escolha = input(">>> ")
            if escolha == "1":
                if UDP:
                    self.scan(min_port, max_port, False, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                else:
                    self.scan(min_port, max_port, False)
            elif escolha == "2":
                if UDP:
                    self.scan(min_port, max_port, True, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                else:
                    self.scan(min_port, max_port, True)
            else:
                print("Escolha um número valido\n")
            if self.portas_fechadas:
                print(colored(f"Porta(s) {self.portas_fechadas[0]}-{self.portas_fechadas[-1]} está(ão) fechada(s)", "red"))
                self.portas_fechadas = []
        except Exception as e:
            print(f"Ocorreu um erro tentando escanear portas --> {e}\n")

    def banner_grab(self, port: int):
        if port not in [22, 23, 80]: # portas em que da pra fazer banner grabbing
            return ''
        try:
            client = socket.socket()
            client.settimeout(5)
            client.connect((self.IP, port))
            banner = client.recv(1024)
            client.close()
            self.achou_banner = True
            return banner
        except:
            return ''

    def scan_network(self):
        try:
            # print(f"{self.networkIP}/{self.mascaraSubRede}")

            print("\nEscolha uma opção: ")
            print("1. Teste extensivo (pode demorar muito)")
            print("2. ARP (pode demandar uso de 'sudo' para rodar este arquivo)")
            escolha = input(">>> ")

            if escolha == "2":
                arp_req_frame = scapy.ARP(pdst = f"{self.networkIP}/{self.mascaraSubRede}")

                broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
                
                broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

                answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 10, verbose = True)[0]
                result = []
                for i in range(0,len(answered_list)):
                    # client_dict = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}
                    # result.append(client_dict)
                    print(f"ip : {answered_list[i][1].psrc}, mac : {answered_list[i][1].hwsrc}")

                return result

            # print(list(ipaddress.ip_network(f"{self.networkIP}/{self.mascaraSubRede}", strict=False).hosts()))

            # min_port = int(input("Escolha o range minimo para escanear: "))
            # max_port = int(input("Escolha o range maximo para escanear: "))
            # for host in list(ipaddress.ip_network(f"{self.networkIP}/{self.mascaraSubRede}", strict=False).hosts()):

            elif escolha == "1":
                for host in ipaddress.IPv4Network(f"{self.networkIP}/{self.mascaraSubRede}"):
                    abertas = []
                    for port in KNOWN_PORTS.keys():
                        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                        client.settimeout(1)
                        r = client.connect_ex((str(host), port))
                        if r == 0:
                            servico = KNOWN_PORTS.get(port)
                            if servico is None:
                                servico = "Serviço desconhecido"
                            print(colored(f"Porta aberta: {port}, {servico}", "green"))
                            abertas.append(port)
                        client.close()

                    if abertas:
                        print(colored(f"Host no IP {str(host)} possui portas abertas nesta rede", on_color="on_green"))

                print("")
        
        except PermissionError:
            print("Não foi possível escanear a rede, tente sair e rodar o script novamente usando 'sudo python main.py'\n")

        except Exception as e:
            print(f"Não foi possível escanear a rede, erro --> {e}")

    def run(self):
        while self.running:
            print("Escolha algo para fazer: ")
            print("1. Definir o IP do host")
            print("2. Definir o IP da rede")
            print("3. Escanear portas (TCP)")
            print("4. Escanear portas (UDP)")
            print("5. Detectar OS")
            print("6. Escanear hosts conectados a sua rede")
            print("0. Sair")
            escolha = input(">>> ")

            if escolha == "1":
                print("\nEscolha IPv4 ou IPV6: ")
                print("1. IPv4")
                print("2. IPv6")
                escolha = input(">>> ")
                if escolha == "1":
                    IP = input("Digite o IP do host: ")
                    if IP.count(".") != 3:
                        print("Digite um IP válido")
                    else:
                        self.IP = IP
                elif escolha == "2":
                    self.IPv6 = input("Digite o IP do host: ")
                else:
                    print("Escolha um número válido\n")
                continue

            elif escolha == "2":
                IP = input("Digite o IP da rede: ")
                if IP.count(".") != 3:
                    print("Digite um IP válido\n")
                else:
                    self.networkIP = IP
                    mascara = input("Digite a máscara de sub-rede: ")
                    if mascara.isdigit() or (mascara.count(".") == 3):
                        self.mascaraSubRede = mascara
                    else:
                        print("Digite uma máscara de sub-rede válida\n")
                continue 

            elif escolha == "3":
                min_port = input("Escolha o range mínimo para escanear: ")
                max_port = input("Escolha o range máximo para escanear: ")
                self.scan_ports(min_port, max_port)
                continue

            elif escolha == "4":
                min_port = input("Escolha o range mínimo para escanear: ")
                max_port = input("Escolha o range máximo para escanear: ")
                self.scan_ports(min_port, max_port, UDP=True)
                continue

            elif escolha == "5":
                self.achou_banner = False
                try:
                    for port in self.portas_abertas:
                        banner = self.banner_grab(port)
                        if banner:
                            print(f"Banner capturado na porta {port} --> {banner}\n")
                except Exception as e:
                    print(f"Não foi possivel identificar o OS usando banner grabbing, erro --> {e}\n")
                if not self.achou_banner:
                    print("Não foi possivel identificar o OS usando banner grabbing\n")
                continue

            elif escolha == "6":
                self.scan_network()

            elif escolha == "0":
                self.running = False
                continue

            else:
                print("Insira um numero valido\n")
                continue

def main():
    scanner = Scanner()
    scanner.run()

if __name__ == "__main__":
    main()
