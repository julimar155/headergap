#!/bin/bash
#--------------------------------CORES-------------------------#

PADRAO="\x1b["
FORMATACOR=$PADRAO"39;49;00m"
RED=$PADRAO"01;31;01m"
GREEN=$PADRAO"01;32;01m"
YELLOW=$PADRAO"01;33;01m"
BLUE=$PADRAO"01;34;01m"
ROSA=$PADRAO"01;35;01m"

#----------------------------------------digitar dominio------------------------------------------#

read -p "digite o dominio desejado:"

#------------------criar arquivo com parametro para o curl utilizar e enviar para alvo.txt--------#
echo 'url='$REPLY > ~/alvo.txt

#------------------------------se existir o arquivo alvo.txt---------------------------------------#
if cat alvo.txt;

#------------entao utilizar o curl neste arquivo extraindo cabeçalho e jogar para headers.txt-----------#
then
	curl -Is --config ~/alvo.txt > headers.txt
#------------se nao existir o arquivo alvo.txt entao crie, extraia seus cabeçalhos e leia a resposta------------#
else
	echo 'url='$REPLY > ~/alvo.txt
	curl -Is --config ~/alvo.txt > headers.txt
fi

#-----------------------------------------filtragem de cabecalhos------------------------------#
        if
                cat  headers.txt | grep "Content-Security-Policy"
        then
                echo -e "$GREEN Content-Security-Policy OK $FORMATACOR"
		echo -e "----------------------------------------------------------------------------------------------------------------------------------------------------"
        else
                echo -e "\n$RED Missing Content-Security-Policy $FORMATACOR\n"
		echo -e "$BLUE Informções sobre a vulnerabilidade: $FORMATACOR \n"
		echo -e "$BLUE CLASSIFICAÇÃO$FORMATACOR:\n $YELLOW LOW $FORMATACOR\n"
		echo -e "$BLUE NOME:\n $FORMATACOR Content Security Policy (CSP) not implemented\n"
		echo -e "$BLUE DESCRIÇÃO:\n $FORMATACOR A Política de Segurança de Conteúdo (CSP) é um padrão de segurança da Web que ajuda a mitigar ataques como cross-site scripting (XSS), clickjacking ou problemas de conteúdo misto. O CSP fornece mecanismos aos sites para restringir o conteúdo que os navegadores poderão carregar.\n"
		echo -e "$BLUE SUGESTÃO DE REPARO:\n $FORMATACOR A Política de Segurança de Conteúdo (CSP) pode ser implementada adicionando um cabeçalho Content-Security-Policy . O valor deste cabeçalho é uma string contendo as diretivas de política que descrevem sua Política de Segurança de Conteúdo. Para implementar o CSP, você deve definir listas de origens permitidas para todos os tipos de recursos que seu site utiliza.\n"
		echo -e "$BLUE REFERÊNCIAS:\n $FORMATACOR https://www.acunetix.com/vulnerabilities/web/content-security-policy-csp-not-implemented/\nhttps://content-security-policy.com/\n\n"
		echo -e "---------------------------------------------------------------------------------------"
	fi

		sleep 4
	if
                cat  headers.txt | egrep -e "Strict-Transport-Security" -e "includeSubDomains;"
        then
                echo -e "$GREEN Strict-Transport-Security OK $FORMATACOR"
		echo -e "----------------------------------------------------------------------------------------------------------------------------------------------------"
        else
                echo -e "$RED Missing Strict-Transport-Security $FORMATACOR\n"
		echo -e "$BLUE Informções sobre a vulnerabilidade: $FORMATACOR \n"
                echo -e "$BLUE CLASSIFICAÇÃO$FORMATACOR:\n $YELLOW LOW $FORMATACOR\n"
                echo -e "$BLUE NOME:\n $FORMATACOR HTTP Strict Transport Security (HSTS) not following best practices\n"
                echo -e "$BLUE DESCRIÇÃO:\n $FORMATACOR O HTTP Strict Transport Security (HSTS) instrui um navegador da Web a se conectar apenas a um site da Web usando HTTPS. Foi detectado que a implementação do HTTP Strict Transport Security (HSTS) do seu aplicativo da Web não é tão rigorosa quanto normalmente é aconselhável"
                echo -e "$BLUE SUGESTÃO DE REPARO:\n $FORMATACOR É recomendável implementar as melhores práticas de HTTP Strict Transport Security (HSTS) em seu aplicativo da web.\n"
                echo -e "$BLUE REFERÊNCIAS:\n $FORMATACOR https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/StrictTransport-Security\n\n"
		echo -e "---------------------------------------------------------------------------------------"

        fi

		sleep 4
	if
                cat  headers.txt | grep  "X-Content-Type-Options"
        then
                echo -e "$GREEN X-Content-Type-Options OK $FORMATACOR"
		echo -e "----------------------------------------------------------------------------------------------------------------------------------------------------"
        else
                echo -e "$RED Missing X-Content-Type-Options $FORMATACOR\n"
                echo -e "$BLUE Informções sobre a vulnerabilidade: $FORMATACOR \n"
                echo -e "$BLUE CLASSIFICAÇÃO$FORMATACOR:\n $YELLOW LOW $FORMATACOR\n"
                echo -e "$BLUE NOME:\n $FORMATACOR Missing 'X-Content-Type-Options' Header\n"
		echo -e "$BLUE DESCRIÇÃO:\n $FORMATACOR O cabeçalho de resposta HTTP X-Content-Type-Options impede que o navegador detecte por MIME uma resposta longe do tipo de conteúdo declarado. O servidor não retornou um cabeçalho X-Content-Type-Options correto, o que significa que este site pode estar em risco de um ataque Cross-Site Scripting (XSS). \n"
                echo -e "$BLUE SUGESTÃO DE REPARO:\n $FORMATACOR Configure seu servidor web para incluir um cabeçalho X-Content-Type-Options com um valor de nosniff \n"
                echo -e "$BLUE REFERÊNCIAS:\n $FORMATACOR https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#xcto\n\n"
		echo -e "---------------------------------------------------------------------------------------"
        fi

		sleep 4
	if
                cat  headers.txt | grep  "X-Frame-Options"
        then
                echo -e "$GREEN X-Frame-Options OK $FORMATACOR\n"
		echo -e "----------------------------------------------------------------------------------------------------------------------------------------------------"
        else
		echo -e "$RED Clickjacking: X-Frame-Options header $FORMATACOR \n"
                echo -e "$BLUE Informções sobre a vulnerabilidade: $FORMATACOR \n"
                echo -e "$BLUE CLASSIFICAÇÃO$FORMATACOR:\n $ROSA MEDIUM $FORMATACOR\n"
                echo -e "$BLUE NOME:\n $FORMATACOR Clickjacking: X-Frame-Options header\n"
                echo -e "$BLUE DESCRIÇÃO:\n $FORMATACOR Clickjacking (ataque de correção da interface do usuário, ataque de correção da interface do usuário, correção da interface do usuário) é uma técnica maliciosa de enganar um usuário da Web para clicar em algo diferente do que o usuário percebe que está clicando, potencialmente revelando informações confidenciais ou assumindo o controle de seu computador enquanto clica em páginas da web aparentemente inócuas. O servidor não retornou um cabeçalho X-Frame-Options com o valor DENY ou SAMEORIGIN, o que significa que este site pode estar em risco de um ataque de clickjacking. O cabeçalho de resposta HTTP X-Frame-Options pode ser usado para indicar se um navegador deve ou não ter permissão para renderizar uma página dentro de um frame ou iframe. Os sites podem usar isso para evitar ataques de clickjacking, garantindo que seu conteúdo não seja incorporado em sites não confiáveis.\n"
                echo -e "$BLUE SUGESTÃO DE REPARO:\n $FORMATACOR Configure seu servidor web para incluir um cabeçalho X-Frame-Options e um cabeçalho CSP com diretiva de ancestrais de quadro.\n"
                echo -e "$BLUE REFERÊNCIAS:\n $FORMATACOR \n The X-Frame-Options response header (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/XFrame-Options) Clickjacking (https://en.wikipedia.org/wiki/Clickjacking) OWASP Clickjacking (https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) Frame Buster Buster (https://stackoverflow.com/questions/958997/frame-buster-buster-buster-codeneeded)\n\n"
		echo -e "---------------------------------------------------------------------------------------"
        fi

		sleep 4
	if
                cat  headers.txt | grep "X-XSS-Protection"
        then
                echo -e "$GREEN X-XSS-Protection OK $FORMATACOR"
		echo -e "----------------------------------------------------------------------------------------------------------------------------------------------------"
        else
                echo -e "$RED Missing X-XSS-Protection $FORMATACOR \n"
                echo -e "$BLUE Informções sobre a vulnerabilidade: $FORMATACOR \n"
                echo -e "$BLUE CLASSIFICAÇÃO$FORMATACOR:\n $YELLOW LOW $FORMATACOR\n"
                echo -e "$BLUE NOME:\n $FORMATACOR Missing 'X-XSS-Protection' Header\n"
                echo -e "$BLUE DESCRIÇÃO:\n $FORMATACOR O cabeçalho de resposta HTTP 'X-XSS-Protection' é um recurso dos navegadores modernos que permite que os sites controlem seus auditores XSS. O servidor não está configurado para retornar um cabeçalho 'X-XSS-Protection', o que significa que qualquer página neste site pode estar sob o risco de um ataque Cross-Site Scripting (XSS). Este URL é sinalizado como um exemplo específico. Se o suporte a navegadores legados não for necessário, é recomendável usar Content-Security-Policy sem permitir scripts embutidos não seguros.\n"
                echo -e "$BLUE SUGESTÃO DE REPARO:\n $FORMATACOR Configure seu servidor web para incluir um cabeçalho 'X-XSS-Protection' com um valor de '1; mode=block' em todas as páginas.\n"
                echo -e "$BLUE REFERÊNCIAS:\n $FORMATACOR \n https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#xxxsp https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection\n\n"
		echo -e "---------------------------------------------------------------------------------------"

        fi

		sleep 4
	if
                cat  headers.txt | grep  "Referrer-Policy"
        then
                echo -e "$GREEN Referrer-Policy OK $FORMATACOR"
		echo -e "----------------------------------------------------------------------------------------------------------------------------------------------------"
        else
               	echo -e "$RED Missing Referrer Policy $FORMATACOR\n"
                echo -e "$BLUE Informções sobre a vulnerabilidade: $FORMATACOR Missing Referrer Policy\n"
                echo -e "$BLUE CLASSIFICAÇÃO$FORMATACOR:\n $YELLOW LOW $FORMATACOR\n"
                echo -e "$BLUE NOME:\n $FORMATACOR Missing Referrer Policy\n"
                echo -e "$BLUE DESCRIÇÃO:\n $FORMATACOR A política do referenciador fornece mecanismos para sites para restringir as informações do referenciador (enviadas no cabeçalho do referenciador) que os navegadores poderão adicionar. Nenhum cabeçalho de política de referência ou configuração de metatag foi detectado.\n"
                echo -e "$BLUE SUGESTÃO DE REPARO:\n $FORMATACOR Configure a política de referência em seu site adicionando o cabeçalho HTTP 'Referrer-Policy' ou o referenciador de metatag em HTML.\n"
                echo -e "$BLUE REFERÊNCIAS:\n $FORMATACOR \n https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy\n\n"
		echo -e "---------------------------------------------------------------------------------------"
        fi

		sleep 4

	if
                cat  headers.txt | grep  "Access-Control-Allow-Origin: *"
        then
                echo -e "$RED Access-Control-Allow-Origin with wildcard (*) value $FORMATACOR\n"
                echo -e "$BLUE Informções sobre a vulnerabilidade: $FORMATACOR Missing Referrer Policy\n"
                echo -e "$BLUE CLASSIFICAÇÃO$FORMATACOR:\n $YELLOW LOW $FORMATACOR\n"
                echo -e "$BLUE NOME:\n $FORMATACOR Access-Control-Allow-Origin header with wildcard (*)value \n"
                echo -e "$BLUE DESCRIÇÃO:\n $FORMATACOR O compartilhamento de recursos entre origens (CORS) é um mecanismo que permite que recursos restritos (por exemplo, fontes) em uma página da Web sejam solicitados de outro domínio fora do domínio de origem do recurso. O cabeçalho Access-Control-Allow-Origin indica se um recurso pode ser compartilhado com base no valor do cabeçalho da solicitação Origin, "*" ou "null" na resposta. Se um site responder com Access-Control-Allow-Origin:* o recurso solicitado permite o compartilhamento com todas as origens. Portanto, qualquer site podem fazer solicitações XHR (XMLHTTPRequest) ao site e acessar as respostas.\n"
                echo -e "$BLUE SUGESTÃO DE REPARO:\n $FORMATACOR Verificar se o header Access-Control-Allow-Origin: * é apropriado para o recurso/resposta.\n"
                echo -e "$BLUE REFERÊNCIAS:\n $FORMATACOR \n https://portswigger.net/research/exploiting-corsmisconfigurations-for-bitcoins-and-bounties \n\n"
		echo -e "---------------------------------------------------------------------------------------"
        fi
