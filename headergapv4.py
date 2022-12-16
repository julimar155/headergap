#!/usr/bin/python

#--> variaveis <--#

import urllib.request
import socket

RED   = "\033[1;31m"
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"

print ("\r\n")
url = input("URL: ")
print ("\r\n")
site = urllib.request.urlopen(url)
content = site.info()

#--> DNS resolver <--#

print (BLUE + "--> Resolving Host <--" + RESET)
print ("\r\n")

#domain = input("Domain: ")
trat = url.replace ("https","")
trat1 = trat.replace (":","")
domain = trat1.replace ("//","")
#print ("Host: ",domain,"IP: ",socket.gethostbyname(domain))
print (domain)
ip = socket.gethostbyname(domain)
print (ip)
print ("\r\n")

#--> verifica headers <--#

print (BLUE + "--> Checking Headers <--" + RESET)
print ("\r\n")

if content['strict-transport-security'.upper()]:
	print ("HSTS -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print ("HSTS -->" + RED + " NOT OK" + RESET)
	print ("\r\n")

if content['X-Content-Type-Options'.upper()]:
	print ("X-Content-Type-Options -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print ("X-Content-Type-Options -->" + RED + " NOT OK" + RESET)
	print ("\r\n")

if content['X-Frame-Options'.upper()]:
	print ("X-Frame-Options -->" + GREEN + " OK" + RESET)
	print ("\r\n")
else:
	print ("X-Frame-Options -->" + RED + " NOT OK" + RESET)
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
	print ("X-XSS-Protection -->" + RED + " NOT OK" + RESET)
	print ("\r\n")

#--> Portscan <--#

	print (BLUE + "--> Initializing Portscan <--" + RESET)
	print ("\r\n")

for port in range (1,81):
	skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	skt.settimeout(1)
	if skt.connect_ex((domain,port)) == 0:
		print (GREEN + "[+] Open",port,"Port [+]" + RESET)
		print ("\r\n")
	else:
		skt.close()

#--> bannergrabbing FTP <--#

FTPport = 21

skt1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
skt1.connect_ex((domain,FTPport))
banner = skt1.recv(128)
if len (banner) >= 128:
	print ("[+] --> " + GREEN + "FTP Banner Found" + RESET + " <-- [+]")
	print ("\r\n")
	print (banner)
	print ("\r\n")
else:
	print ("Banner Not Found")
	print ("\r\n")
