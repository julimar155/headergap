#!/usr/bin/python

#--> variaveis <--#

import colorama
from colorama import Fore
import urllib.request
import socket

RED   = "\033[1;31m"
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"
MAGENTA = '\033[35m'
YELLOW = '\033[33m'
BLACK = '\033[30m'

#--> variaveis de classificacao <--


print ("\r\n")
url = input("URL: ")
print ("\r\n")
site = urllib.request.urlopen(url)
content = site.info()

#--> DNS resolver <--#
print (REVERSE + CYAN + "DNS Resolver" + RESET)
print ("\r\n")
#domain = input("Domain: ")
trat = url.replace ("https","")
trat1 = trat.replace (":","")
domain = trat1.replace ("//","")
#print ("Host: ",domain,"IP: ",socket.gethostbyname(domain))
print ("Domain: " + MAGENTA + domain + RESET)
print ("\r\n")
ip = socket.gethostbyname(domain)
print ("IP: ",ip)
print ("\r\n")

#--> verifica headers <--#
print (REVERSE + CYAN + "Header Analisys" + RESET)
print ("\r\n")
if content['strict-transport-security'.upper()]:
	print ("HSTS -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print (RED + REVERSE + "HSTS --> NOT OK" + RESET)
	print ("\r\n")
	print (MAGENTA + "Informções sobre a vulnerabilidade:" + RESET)
	print ("\r\n")
	print (MAGENTA + "Classification:" + RESET + " MEDIUM")
	print ("\r\n")
	print (MAGENTA + "Name:" + RESET + " HTTP Strict Transport Security (HSTS) not implemented")
	print ("\r\n")
	print (MAGENTA + "Description:" + RESET + " O HTTP Strict Transport Security (HSTS) instrui um navegador da Web a se conectar apenas a um site da Web usando HTTPS. Foi detectado que a implementação do HTTP Strict Transport Security (HSTS) do seu aplicativo da Web não é tão rigorosa quanto normalmente é aconselhável")
	print ("\r\n")
	print (MAGENTA + "Mitigation:" + RESET + " É recomendável implementar as melhores práticas de HTTP Strict Transport Security (HSTS) em seu aplicativo da web.")
	print ("\r\n")

if content['X-Content-Type-Options'.upper()]:
	print ("X-Content-Type-Options -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print (RED + REVERSE + "X-Content-Type-Options --> NOT OK" + RESET)
	print ("\r\n")
	print (MAGENTA + "Informções sobre a vulnerabilidade:" + RESET)
	print ("\r\n")
	print (MAGENTA + "Classification:" + RESET + " LOW")
	print ("\r\n")
	print (MAGENTA + "Name:" + RESET + " Missing 'X-Content-Type-Options")
	print ("\r\n")
	print (MAGENTA + "Description:" + RESET + " O cabeçalho de resposta HTTP X-Content-Type-Options impede que o navegador detecte por MIME uma resposta longe do tipo de conteúdo declarado. O servidor não retornou um cabeçalho X-Content-Type-Options correto, o que significa que este site pode estar em risco de um ataque Cross-Site Scripting (XSS).")
	print ("\r\n")
	print (MAGENTA + "Mitigation:" + RESET + " Configure seu servidor web para incluir um cabeçalho X-Content-Type-Options com um valor de nosniff")
	print ("\r\n")

if content['X-Frame-Options'.upper()]:
	print ("X-Frame-Options -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print (REVERSE + RED +  "X-Frame-Options --> NOT OK" + RESET)
	print ("\r\n")
	print (MAGENTA + "Informções sobre a vulnerabilidade:" + RESET)
	print ("\r\n")
	print (MAGENTA + "Classification:" + RESET + " MEDIUM")
	print ("\r\n")
	print (MAGENTA + "Name:" + RESET + " X-Frame-Options header")
	print ("\r\n")
	print (MAGENTA + "Description:" + RESET + " Clickjacking (ataque de correção da interface do usuário, ataque de correção da interface do usuário, correção da interface do usuário) é uma técnica maliciosa de enganar um usuário da Web para que clique em algo diferente do que o usuário percebe que está clicando, potencialmente revelando informações confidenciais ou assumindo o controle de seu computador enquanto clicando em páginas da web aparentemente inócuas.")
	print ("\r\n")
	print (MAGENTA + "Mitigation:" + RESET + " Configure seu servidor web para incluir um cabeçalho X-Frame-Options e um cabeçalho CSP com a diretiva frame-ancestors. Consulte as referências da Web para obter mais informações sobre os valores possíveis para esse cabeçalho.")
	print ("\r\n")

if content['content-security-policy'.upper()]:
	print ("CSP -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print ("CSP -->" + RED + " NOT OK" + RESET)
	print ("\r\n")

if content['X-XSS-Protection'.upper()]:
	print ("X-XSS-Protection -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print (REVERSE + RED + "X-XSS-Protection --> NOT OK" + RESET)
	print ("\r\n")

#--> Portscan <--#

for port in range (1,65536):
	skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	if skt.connect_ex((domain,port)) == 0:
		print ("[+] Open",port,"Port [+]")
	else:
		skt.close()

#--> bannergrabbing FTP <--#

FTPport = 21

skt1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
skt1.connect_ex((domain,FTPport))
banner = skt1.recv(128)
if len (banner) >= 128:
	print (BLUE + "[+] --> FTP Banner Found <-- [+]" + RESET)
	print ("\r\n")
	print (banner)
	print ("\r\n")
else:
	print ("Banner Not Found")
	print ("\r\n")
