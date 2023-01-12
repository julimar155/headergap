#!/usr/bin/python

#--> variaveis <--#

import colorama
from colorama import Fore
import urllib.request
import socket
import sys

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
url = sys.argv[1]
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
	print (REVERSE + RED + "HSTS --> NOT OK" + RESET)
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
	print (REVERSE + RED + "X-Content-Type-Options --> NOT OK" + RESET)
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
	print ("Content Security Policy -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print (REVERSE + RED + "Content Security Policy --> NOT OK" + RESET)
	print ("\r\n")
	print (MAGENTA + "Informções sobre a vulnerabilidade:" + RESET)
	print ("\r\n")
	print (MAGENTA + "Classification:" + RESET + " LOW")
	print ("\r\n")
	print (MAGENTA + "Name:" + RESET + " Content Security Policy (CSP) not implemented")
	print ("\r\n")
	print (MAGENTA + "Description:" + RESET + " A Política de Segurança de Conteúdo (CSP) é uma camada adicional de segurança que ajuda a detectar e mitigar certos tipos de ataques, incluindo Cross Site Scripting (XSS) e ataques de injeção de dados. A Política de Segurança de Conteúdo (CSP) pode ser implementada adicionando um Cabeçalho de política de segurança de conteúdo. O valor deste cabeçalho é uma string contendo as diretivas de política que descrevem sua Política de Segurança de Conteúdo. Para implementar o CSP, você deve definir listas de origens permitidas para todos os tipos de recursos que seu site utiliza. Por exemplo, se você tem um site simples que precisa carregar scripts, folhas de estilo e imagens hospedadas localmente, bem como da biblioteca jQuery de seu CDN, o cabeçalho CSP pode ter a seguinte aparência: Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com; Foi detectado que seu aplicativo Web não implementa a Política de Segurança de Conteúdo (CSP) porque o cabeçalho CSP está ausente da resposta. É recomendável implementar a Política de Segurança de Conteúdo (CSP) em seu aplicativo da web.")
	print ("\r\n")
	print (MAGENTA + "Mitigation:" + RESET + " É recomendável implementar a Política de Segurança de Conteúdo (CSP) em seu aplicativo da web. A configuração do Content SecurityPolicy envolve adicionar o cabeçalho HTTP Content-Security-Policy a uma página da Web e fornecer valores para controlar os recursos que o agente do usuário tem permissão para carregar para essa página.")
	print ("\r\n")


if content['X-XSS-Protection'.upper()]:
	print ("X-XSS-Protection -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print (REVERSE + RED + "X-XSS-Protection --> NOT OK" + RESET)
	print ("\r\n")
	print (MAGENTA + "Informções sobre a vulnerabilidade:" + RESET)
	print ("\r\n")
	print (MAGENTA + "Classification:" + RESET + " LOW")
	print ("\r\n")
	print (MAGENTA + "Name:" + RESET + " Missing X-XSS-Protection")
	print ("\r\n")
	print (MAGENTA + "Description:" + RESET + " O cabeçalho de resposta HTTP 'X-XSS-Protection' é um recurso dos navegadores modernos que permite que os sites controlem seus auditores XSS. O servidor não está configurado para retornar um cabeçalho 'X-XSS-Protection', o que significa que qualquer página neste site pode estar sob o risco de um ataque Cross-Site Scripting (XSS). Este URL é sinalizado como um exemplo específico. Se o suporte a navegadores legados não for necessário, é recomendável usar Content-Security-Policy sem permitir scripts embutidos não seguros.")
	print ("\r\n")
	print (MAGENTA + "Mitigation:" + RESET + " Configure seu servidor web para incluir um cabeçalho 'X-XSS-Protection' com um valor de '1; mode=block' em todas as páginas.")
	print ("\r\n")

if content['Referrer-Policy'.upper()]:
	print ("Referrer-Policy -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print (REVERSE + RED + "Referrer-Policy --> NOT OK" + RESET)
	print ("\r\n")
	print (MAGENTA + "Informções sobre a vulnerabilidade:" + RESET)
	print ("\r\n")
	print (MAGENTA + "Classification:" + RESET + " LOW")
	print ("\r\n")
	print (MAGENTA + "Name:" + RESET + " Missing Referrer Policy")
	print ("\r\n")
	print (MAGENTA + "Description:" + RESET + " A política do referenciador fornece mecanismos para sites para restringir as informações do referenciador (enviadas no cabeçalho do referenciador) que os navegadores poderão adicionar. Nenhum cabeçalho de política de referência ou configuração de metatag foi detectado.")
	print ("\r\n")
	print (MAGENTA + "Mitigation:" + RESET + " Configure a política de referência em seu site adicionando o cabeçalho HTTP 'Referrer-Policy' ou o referenciador de metatag em HTML.")
	print ("\r\n")


#--> Portscan <--#

#for port in range (1,65536):
#	skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#	skt.settimeout(0.01)
#	if skt.connect_ex((domain,port)) == 0:
#		print ("[+] Open",port,"Port [+]")
#	else:
#		skt.close()

#--> bannergrabbing FTP <--#

#FTPport = 21

#skt1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#skt1.connect_ex((domain,FTPport))
#banner = skt1.recv(128)
#if len (banner) >= 128:
#	print (BLUE + "[+] --> FTP Banner Found <-- [+]" + RESET)
#	print ("\r\n")
#	print (banner)
#	print ("\r\n")
#else:
#	print ("Banner Not Found")
#	print ("\r\n")
