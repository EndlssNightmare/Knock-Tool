#!/usr/bin/python3
import sys
import signal
from time import sleep
from scapy.all import IP, TCP, sr1

def banner():

    print("")
    print("  _  __                 _      _______          _ ")
    print(" | |/ /                | |    |__   __|        | |")
    print(" | ' / _ __   ___   ___| | __    | | ___   ___ | |")
    print(" |  < | '_ \ / _ \ / __| |/ /    | |/ _ \ / _ \| |")
    print(" | . \| | | | (_) | (__|   <     | | (_) | (_) | |")
    print(" |_|\_\_| |_|\___/ \___|_|\_\    |_|\___/ \___/|_|")
    print("")
    print("Author: https://github.com/EndlssNightmare\n")
    print("Author: https://github.com/LucasMoreirac\n")

def print_help():
    print("Modo de uso: python3 knocktool.py [OPÇÕES]")
    print("Opções:")
    print("  -h, --help         Mostra este menu de ajuda")
    print("  -i, --ip <IP>          Endereço IP a ser usado")
    print("  -p, --portas <PORTAS>          Número de portas separadas por vírgula")
    print("  -f, --flag <FLAG>          Flag a ser enviada (ex: SYN, FIN)")

def __Ctrl_c__(signum, frame):
    print("\nAbortando script")
    sys.exit(0)

signal.signal(signal.SIGINT, __Ctrl_c__)

def parse_args():
    args = {"ip": None, "portas": None, "flag": False}

    i = 1
    while i < len(sys.argv):

        if sys.argv[i] in ("-h", "--help"):
            print_help()
            sys.exit(0)

        elif sys.argv[i] in ("-i", "--ip"):
            args["ip"] = sys.argv[i + 1]
            i += 2

        elif sys.argv[i] in ("-p", "--portas"):
            args["portas"] = sys.argv[i + 1].split(",")
            i += 2

        elif sys.argv[i] in ("-f", "--flag"):
            if i + 1 < len(sys.argv):
                flag = sys.argv[i + 1].upper() # Convertendo a flag para maiúsculas

                if flag.upper() not in ("S", "F"):
                    print("Flag inválida. Use apenas as flags SYN ou FIN")
                    sys.exit(1)

                args["flag"] = flag
            else:
                args["flag"] = "S"
            i += 2

        else:
            print("Opção inválida:", sys.argv[i])
            print_help()
            sys.exit(1)

    if args["ip"] is None or args["portas"] is None:
        print("Endereço IP e portas são obrigatórios!")
        sys.exit(1)

    return args

def main():
    banner()
    if len(sys.argv) <=1:
        print("Modo de uso: python3 knocktool.py -i 192.168.0.17 -p 25,443,7777,5353,22 -f S\n")
        print("Menu: -h, --help")
        return

    args = parse_args() # Chama parse_args() para obter os argumentos

    ip = args["ip"]
    portas = args["portas"]
    flag = args["flag"] if args["flag"] else "S" #Converte a flag para maiúscula

    for porta in portas:
        try:
            pacote = IP(dst=ip)/TCP(dport=int(porta), flags=flag)
            resposta = sr1(pacote, timeout=1, verbose=False)

            if resposta and (resposta.haslayer(TCP) and resposta.getlayer(TCP).flags == 0x12):
                print("Knock...")
                sleep(1)
                print(f"[+] Porta {porta} aberta! [+]")
            else:
                print("knock...")
                sleep(1)
                print(f"[-] Porta {porta} fechada! [-]")
        except Exception as e:
            print(f"Erro ao escanear porta {porta}: {e}")

if __name__ == '__main__':
    main()
         
