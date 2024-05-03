# Knock-Tool - Port Knocking Tool
[![Python 2.7|3.4|3.9](https://img.shields.io/badge/python-2.7|3.4|3.9-yellow.svg)](https://www.python.org/)

Knock-Tool has been created to facilitate the task of sending SYN packets to multiple ports.

## Screenshots

![](https://raw.githubusercontent.com/EndlssNightmare/Knock-Tool/main/images/KnockTool1.png)
![](https://raw.githubusercontent.com/EndlssNightmare/Knock-Tool/main/images/KnockTool2.png)

## Installation

To install Knock-tool follow the steps:

```
git clone https://github.com/EndlssNightmare/Knock-Tool.git
```

To install requirements:

```
pip3 install -r requirements.txt
```

## Usage

To get a list of basic options and switches use:

```sh
$ python3 knocktool.py -h
```

### Options

```
  -h, --help         Mostra este menu de ajuda
  -i, --ip <IP>          Endereço IP a ser usado
  -p, --ports <PORTAS>          Número de portas separadas por vírgula
  -f, --flag <FLAG>          Flag a ser enviada (default: SYN)
  -c, --close           Inverte as portas passadas pelo usuário
  -pv, --port-verify <PORTA>         Verifica uma porta após o Knocking (Ex: 22)
  -v, --verbose          Mostra informações adicionais
  -ver, --version   Mostra a versão do programa
```
