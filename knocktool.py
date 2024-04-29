#!/usr/bin/python3
import sys
import os
import signal
from time import sleep
from scapy.all import IP, TCP, sr1, srp
from scapy.layers.inet import ICMP
from scapy.layers.l2 import ARP, Ether
from colorama import init, Fore, Style

init()

VERSION = "1.0"

def banner():
    print(Fore.LIGHTRED_EX + "")
    print(" ██ ▄█▀ ███▄    █  ▒█████   ▄████▄   ██ ▄█▀   ▄▄▄█████▓ ▒█████   ▒█████   ██▓    ")
    print(" ██▄█▒  ██ ▀█   █ ▒██▒  ██▒▒██▀ ▀█   ██▄█▒    ▓  ██▒ ▓▒▒██▒  ██▒▒██▒  ██▒▓██▒    ")
    print("▓███▄░ ▓██  ▀█ ██▒▒██░  ██▒▒▓█    ▄ ▓███▄░    ▒ ▓██░ ▒░▒██░  ██▒▒██░  ██▒▒██░    ")
    print("▓██ █▄ ▓██▒  ▐▌██▒▒██   ██░▒▓▓▄ ▄██▒▓██ █▄    ░ ▓██▓ ░ ▒██   ██░▒██   ██░▒██░    ")
    print("▒██▒ █▄▒██░   ▓██░░ ████▓▒░▒ ▓███▀ ░▒██▒ █▄     ▒██▒ ░ ░ ████▓▒░░ ████▓▒░░██████▒")
    print("▒ ▒▒ ▓▒░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ░▒ ▒  ░▒ ▒▒ ▓▒     ▒ ░░   ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░")
    print("░ ░▒ ▒░░ ░░   ░ ▒░  ░ ▒ ▒░   ░  ▒   ░ ░▒ ▒░       ░      ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░")
    print("░ ░░ ░    ░   ░ ░ ░ ░ ░ ▒  ░        ░ ░░ ░      ░      ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░   ")
    print("░  ░            ░     ░ ░  ░ ░      ░  ░                   ░ ░      ░ ░      ░  ░")
    print("                           ░                                                     ")
    print("Author: https://github.com/EndlssNightmare")
    print("Author: https://github.com/LucasMoreiraC\n")
    print(Fore.RESET, end='')

def print_help():
    print(Fore.CYAN + "")
    print("Modo de uso: python3 knock.py [OPÇÕES]\n")
    print("Exemplos: python3 knock.py -i 192.168.0.129 -p 300,3000,5353,4545 -f s -pv 22")
    print("          python3 knock.py -i 192.168.0.129 -p 300,3000,5353,4545 -f s -pv 22 -v -c\n")
    print("Opções:\n")
    print("  -h, --help         Mostra este menu de ajuda")
    print("  -i, --ip <IP>          Endereço IP a ser usado")
    print("  -p, --ports <PORTAS>          Número de portas separadas por vírgula")
    print("  -f, --flag <FLAG>          Flag a ser enviada (default: SYN)")
    print("  -c, --close           Inverte as portas passadas pelo usuário")
    print("  -pv, --port-verify <PORTA>         Verifica uma porta após o Knocking (Ex: 22)")
    print("  -v, --verbose          Mostra informações adicionais")
    print("  -ver, --version   Mostra a versão do programa")
    print(Fore.RESET, end='')

def __Ctrl_c__(signum, frame):
    print(Fore.LIGHTRED_EX + "\n[!] Abortando script! [!]")
    print(Fore.RESET, end='')
    sys.exit(0)

signal.signal(signal.SIGINT, __Ctrl_c__)

def parse_args():
    args = {"ip": None, "portas": None, "flag": False, "close": False, "port_verify": None, "verbose": False}

    i = 1

    while i < len(sys.argv):

        if sys.argv[i] in ("-h", "--help"):
            print_help()
            sys.exit(0)

        elif sys.argv[i] in ("-i", "--ip"):
            if i + 1 < len(sys.argv):
                args["ip"] = sys.argv[i + 1]
                i += 2

            else:
                print(Fore.LIGHTRED_EX + "[?] Endereço IP não especificado! [?]")
                print_help()
                sys.exit(1)

        elif sys.argv[i] in ("-p", "--ports"):
            if i + 1 < len(sys.argv):
                args["portas"] = sys.argv[i + 1].split(",")
                i += 2

            else:
                print(Fore.LIGHTRED_EX + "[?]  Portas não especificadas! [?]")
                print(Fore.RESET, end='')
                print_help()
                sys.exit(1)

        elif sys.argv[i] in ("-f", "--flag"):
            if i + 1 < len(sys.argv):
                flag = sys.argv[i + 1].upper()

                if flag in ("SYN", "syn"):
                    flag = "S"

                elif flag in ("FIN", "fin"):
                    flag = "F"

                elif flag != "S" and flag != "F":
                    print(Fore.LIGHTRED_EX + f"Flag {flag} inválida. Use apenas as flags S ou F")
                    print(Fore.RESET, end='')
                    sys.exit(1)

                args["flag"] = flag
            else:
                args["flag"] = "S"
            i += 2

        elif sys.argv[i] in ("-c", "--close"):
            args["close"] = True
            i += 1

        elif sys.argv[i] in ("-pv", "--port-verify"):
            if i + 1 < len(sys.argv):
                args["port_verify"] = sys.argv[i + 1]
                i += 2

            else:
                print(Fore.LIGHTRED_EX + "[?] Porta para verificar não especificada! [?]")
                print_help()
                sys.exit(1)

        elif sys.argv[i] in ("-v", "--verbose"):
            args["verbose"] = True
            i += 1

        elif sys.argv[i] in ("-ver", "--version"):
            print(Fore.CYAN + f"Versão atual: {VERSION}")
            sys.exit(0)

        else:
            print(Fore.LIGHTRED_EX + "Opção inválida:", sys.argv[i])
            print(Fore.RESET, end='')
            print_help()
            sleep(1)
            sys.exit(1)

    if args["ip"] is None or args["portas"] is None:
        print(Fore.LIGHTRED_EX + "[!] Endereço IP e portas são obrigatórios! [!]")
        print(Fore.RESET, end='')
        sleep(1)
        sys.exit(1)

    return args

def check_icmp_active(ip, verboss=False):
    try:

        print(Fore.LIGHTYELLOW_EX + f"[*] Verificando se o Host {ip} está ativo! [*]")
        print(Fore.RESET, end='')
        sleep(1)

        if verboss:
            print(Fore.LIGHTYELLOW_EX + "[*]  Enviando pacote ICMP! [*]")
            print(Fore.RESET, end='')
            sleep(1)

        response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=False)

        if response:
            if verboss:
                print(Fore.LIGHTGREEN_EX + "[+] Pacote ICMP enviado. [+]")
                print(Fore.RESET, end='')
                sleep(1)

            print(Fore.LIGHTGREEN_EX + f"[+] Host is up! [+]")
            print(Fore.RESET, end='')
            sleep(1)
            return True

        else:
            print(Fore.MAGENTA + "[-] Falha ao enviar pacote ICMP!  [-]")
            print(Fore.RESET, end='')
            sleep(1)
            return False

    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[!] Erro ao verificar se o alvo permite ICMP: {e} [!]")
        print(Fore.RESET, end='')
        sleep(1)
        return False

def check_arp_active(ip, verboss=False):
    try:
        print(Fore.LIGHTYELLOW_EX + f"[*] Verificando se o Host {ip} está ativo! [*]")
        print(Fore.RESET, end='')
        sleep(1)

        if verboss:
            print(Fore.LIGHTYELLOW_EX + "[*] Enviando pacote ARP! [*]")
            print(Fore.RESET, end='')
            sleep(1)

        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        respost = srp(arp_request, timeout=2, verbose=False)[0]

        if respost:
            if verboss:
                print(Fore.LIGHTYELLOW_EX + "[*] Pacote ARP enviado! [*]")
                print(Fore.RESET, end='')
                sleep(1)

            print(Fore.LIGHTGREEN_EX + "[+] Host is up! [+]")
            print(Fore.RESET, end='')
            sleep(1)
            return True

        else:
            print(Fore.MAGENTA + "[-] Falha ao enviar pacote ARP [-]")
            print(Fore.RESET, end='')
            sleep(1)
            return False

    except Exception as e:
        print(Fore.LIGHTRED_EX + f"[!] Erro ao verificar se o alvo permite ARP: {e} [!]")
        print(Fore.RESET, end='')
        sleep(1)
        return False

def main():
    banner()
    if len(sys.argv) <=1:
        print(Fore.CYAN + "Modo de uso: python3 knock.py -i 192.168.0.17 -p 25,443,7777,5353 -f syn -pv 22\n")
        print("Menu: -h, --help")
        print(Fore.RESET, end='')
        return

    args = parse_args()

    ip = args["ip"]
    portas = args["portas"]
    flag = args["flag"] if args["flag"] else "S"
    verboss = args["verbose"]


    if args["close"]:
        portas = portas[::-1]

    if check_icmp_active(ip, verboss):
        print(Fore.LIGHTYELLOW_EX + f"[*] Iniciando knocking em {ip} [*]")
        print(Fore.RESET, end='')
        sleep(1)

    else:
        print(Fore.LIGHTRED_EX + f"[!] ICMP indisponível! Enviando ARP para verificar se o Host {ip} está ativo... [!]")
        print(Fore.RESET, end='')
        sleep(1)

        if check_arp_active(ip, verboss):
            print(Fore.LIGHTYELLOW_EX + f"[*] Iniciando knocking em {ip} [*]")
            print(Fore.RESET, end='')
            sleep(1)

        else:
            print(Fore.LIGHTRED_EX + "[!] ARP indisponível! O alvo não está ativo. Port knocking não será realizado. [!]")
            print(Fore.RESET, end='')
            sleep(1)
            return

    for porta in portas:
        try:
            pacote = IP(dst=ip)/TCP(dport=int(porta), flags=flag)
            resposta = sr1(pacote, timeout=1, verbose=False)

            if resposta and (resposta.haslayer(TCP) and resposta.getlayer(TCP).flags == 0x12):
                print(Fore.LIGHTGREEN_EX + f"[+]Knock... Porta {porta} aberta! [+]")
                print(Fore.RESET, end='')
                sleep(1)

            else:
                print(Fore.MAGENTA + f"[-]Knock... Porta {porta} fechada! [-]")
                print(Fore.RESET, end='')
                sleep(1)

        except Exception as e:
            print(Fore.LIGHTRED_EX + f"[!] Erro ao escanear porta {porta}: {e} [!]")
            print(Fore.RESET, end='')
            sleep(1)

    if args["port_verify"]:
        try:
            open_port = int(args["port_verify"])
            print(Fore.LIGHTYELLOW_EX + f"[*] Verificando porta {open_port} em {ip} após o knocking padrão... [*]")
            print(Fore.RESET, end='')
            sleep(1)

            reesp = sr1(IP(dst=ip)/TCP(dport=open_port), timeout=1, verbose=False)

            if reesp and (reesp.haslayer(TCP) and reesp.getlayer(TCP).flags == 0x12):
                print(Fore.LIGHTGREEN_EX + f"[+] Porta {open_port} está aberta! [+]")
                print(Fore.RESET, end='')
                sleep(1)

            else:
                print(Fore.MAGENTA + f"[-] Porta {open_port} está fechada! [-]")
                print(Fore.RESET, end='')
                sleep(1)

        except Exception as e:
            print(Fore.LIGHTRED_EX + f"[!] Erro ao verificar porta {args['port_verify']}: {e} [!]")
            print(Fore.RESET, end='')
            sleep(1)

if __name__ == '__main__':
    main()
    
