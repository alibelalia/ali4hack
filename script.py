import sys
import os
import time
import random
class color:
    HEADER = '\033[95m'
    IMPORTANT = '\33[35m'
    NOTICE = '\033[33m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'
    LOGGING = '\33[34m'
def info():
    print(color.RED + ''' ___ _   _ _____ ___  
|_ _| \ | |  ___/ _ \ 
 | ||  \| | |_ | | | |
 | || |\  |  _|| |_| |
|___|_| \_|_|   \___/ 
                      
    ''' + color.END)
    
    print("INformation Gathering Section")
    try:

        print('''
        {1}--Nmap - Network Mapper
        {2}--Setoolkit
        {3}--Host To IP
        {4}--WPScan
        {5}--CMSmap
        {6}--XSStrike
        {7}--Doork
        {8}--Crips
        {9}-Exit
        ''')
        choice = input("Enter Your Choice: ")
        if choice=='1':
            os.system("sudo apt-get install nmap -y && nmap -h")

            info()
        elif choice=='2':
            os.system("sudo git clone https://github.com/trustedsec/social-engineer-toolkit.git")
            info()
        elif choice=='3':
            os.system("clear")
            print(color.RED + ''' _   _           _     ____    ___ ____  
| | | | ___  ___| |_  |___ \  |_ _|  _ \ 
| |_| |/ _ \/ __| __|   __) |  | || |_) |
|  _  | (_) \__ \ |_   / __/   | ||  __/ 
|_| |_|\___/|___/\__| |_____| |___|_|    
                                         
''' + color.END)
            import socket
            target = input("Enter Your Target URL: ")
            ip = socket.gethostbyname(target)
            print("your Target IP: ", ip)
            sys.exit()
        elif choice=='4':
            os.system("sudo git clone https://github.com/wpscanteam/wpscan.git")
            info()
        elif choice=='5':
            os.system("sudo git clone https://github.com/Dionach/CMSmap.git")
            info()
        elif choice=='6':
            os.system("sudo git clone https://github.com/UltimateHackers/XSStrike.git")
            info()
        elif choice=='7':
            os.system("sudo git clone https://github.com/AeonDave/doork.git")
            info()
        elif choice=='8':
            os.system("sudo git clone https://github.com/Manisso/Crips.git")
            info()
        elif choice=='9':
            print("Exiting...")
            time.sleep(5)
            sys.exit()
        else:

            print("unvalid choice")
            time.sleep(3)
            info()
    except KeyboardInterrupt:
        print("Godd Bye...See You Later..\n")
        sys.exit()

def passattack():
    print(color.RED + ''' ____                  _   _   _             _    
|  _ \ __ _ ___ ___   / \ | |_| |_ __ _  ___| | __
| |_) / _` / __/ __| / _ \| __| __/ _` |/ __| |/ /
|  __/ (_| \__ \__ \/ ___ \ |_| || (_| | (__|   < 
|_|   \__,_|___/___/_/   \_\__|\__\__,_|\___|_|\_\
                                                  
    '''+ color.END)
    print("PassWord Attack Section")
    try:

        print('''
        {1}--Cupp - Common User Passwords Profiler
        {2}--BruteX - Automatically bruteforces all services running on a target
        {3}--Exit''')
        choice2 = input("Enter Your Choice: ")
        if choice2=='1':
            os.system("sudo git clone https://github.com/Mebus/cupp.git")
            passattack()
        elif choice2=='2':
            os.system("sudo git clone https://github.com/1N3/BruteX.git")
            passattack()
        elif choice2=='3':
            print("Good Bye....See You Later...")
            time.sleep(5)
            sys.exit()
        else:
            print("Unvalid Choice")
            print("Exiting..")
            time.sleep(4)
            sys.exit()

    except KeyboardInterrupt:
        print("Exiting....\n")
        time.sleep(4)
        sys.exit()
def wireless():
    print(color.RED + '''
    └──╼ $figlet Wireless
__        ___          _               
\ \      / (_)_ __ ___| | ___  ___ ___ 
 \ \ /\ / /| | '__/ _ \ |/ _ \/ __/ __|
  \ V  V / | | | |  __/ |  __/\__ \__ \
   \_/\_/  |_|_|  \___|_|\___||___/___/
                                       
''' + color.END)
    print("Wireless Tools Section")
    try:

        print('''
        {1}--reaver
        {2}--pixiewps
        {3}-Exit ''')
        choice3 = input("Enter Your Choice: ")
        if choice3=='1':
            os.system("sudo apt-get install reaver -y")
            wireless()
        elif choice3=='2':
            os.system("sudo apt-get install pixiewps -y")
            wireless()
        elif choice3=='3':
            print("Exiting.....")
            time.sleep(4)
            sys.exit()
        else:
            print("Unvalid Choice...")
            print("Exiting.....")
            time.sleep(4)
            sys.exit()
    except KeyboardInterrupt:
        print("Good...Bye..Se You Later....\n")
        time.sleep(4)
        sys.exit()
def expl():
    print(color.RED + '''  _____            _       _ _        _   _             
| ____|_  ___ __ | | ___ (_) |_ __ _| |_(_) ___  _ __  
|  _| \ \/ / '_ \| |/ _ \| | __/ _` | __| |/ _ \| '_ \ 
| |___ >  <| |_) | | (_) | | || (_| | |_| | (_) | | | |
|_____/_/\_\ .__/|_|\___/|_|\__\__,_|\__|_|\___/|_| |_|
           |_|                                         '''+ color.END)
    print("Exploitation Tools Section")
    try:
        print('''
        {1}--ATSCAN
        {2}--sqlmap
        {3}--commix
        {4}--FTP Auto Bypass
        {5}--JBoss-Autopwn
        {6}--Blind SQL Automatic Injection And Exploit
        {7}--Bruteforce the Android Passcode given the hash and salt
        {8}--Joomla SQL injection Scanner
        {9}--Exit....''')
        choice4 = input("Enter Your Choice: ")
        if choice4=='1':
            os.system("sudo git clone https://github.com/AlisamTechnology/ATSCAN.git && cd ATSCAN && sudo perl atscan.pl")
            sys.exit()
        elif choice4=='2':
            print ("usage: python sqlmap.py -h")
            time.sleep(3)
            os.system("sudo apt-get install sqlmap -y")
            sys.exit()
        elif choice4=='3':
            print ("Automated All-in-One OS Command Injection and Exploitation Tool.")
            print ("usage: commix.py --help")
            time.sleep(3)
            os.system("sudo apt-get install commix")
            sys.exit()
        elif choice4=='4':
            print("Abusing authentication bypass of Open&Compact (Gabriel's)")
            os.system("sudo wget http://pastebin.com/raw/Szg20yUh --output-document=gabriel.py")
            os.system("clear")
            os.system("sudo python2 gabriel.py")
            ftpbypass = input("Enter Target IP and Use Command:")
            os.system("sudo python gabriel.py %s" % ftpbypass)
            sys.exit()
        elif choice4=='5':
            os.system("clear")
            print ("This JBoss script deploys a JSP shell on the target JBoss AS server. Once")
            print ("deployed, the script uses its upload and command execution capability to")
            print ("provide an interactive session.")
            print ("")
            os.system("sudo git clone https://github.com/SpiderLabs/jboss-autopwn.git")
            sys.exit()
        elif choice4=='6':
            print("This tool will only work on blind sql injection")
            cbsq = input("select target: ")
            os.system("sudo wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/bsqlbf-v2/bsqlbf-v2-7.pl -o bsqlbf.pl")
            os.system("sudo perl bsqlbf.pl -url %s" % cbsq)
            os.system("sudo rm bsqlbf.pl")
        elif choice4=='7':
            key = input("Enter the android hash: ")
            salt = input("Enter the android salt: ")
            os.system("sudo git clone https://github.com/PentesterES/AndroidPINCrack.git")
            os.system("cd AndroidPINCrack && sudo python AndroidPINCrack.py -H %s -s %s" % (key, salt))
            sys.exit()
        elif choice4=='8':
            print("your target must be Joomla, Mambo, PHP-Nuke, and XOOPS Only ")
            target = input("Select a target: ")
            os.system("sudo wget https://dl.packetstormsecurity.net/UNIX/scanners/cms_few.py.txt -O cms.py")
            os.system("sudo python cms.py %s" % target)
            sys.exit()
        elif choice4=='9':
            print("Good...Bye..See You Later....")
            time.sleep(4)
            sys.exit()
        else:
            print("Unvalid Choice...")
            print("")
            print("Exiting...")
            time.sleep(4)
            sys.exit()

    except KeyboardInterrupt:
        print("Exiting....\n")
        time.sleep(4)
        sys.exit()
def sniffingSpoofing():
    print(color.RED + '''  ____  _   _ ___ _____ _____ ___ _   _  ____ 
/ ___|| \ | |_ _|  ___|  ___|_ _| \ | |/ ___|
\___ \|  \| || || |_  | |_   | ||  \| | |  _ 
 ___) | |\  || ||  _| |  _|  | || |\  | |_| |
|____/|_| \_|___|_|   |_|   |___|_| \_|\____|
                                             
''' + color.END)
    print("Sniffing & Spoofing Section")
    try:
        print('''
        {1}--SEToolkit - Tool aimed at penetration testing around Social-Engineering
        {2}--SSLtrip - MITM tool that implements SSL stripping  attacks
        {3}--pyPISHER - Tool to create a mallicious website for password pishing
        {4}--SMTP Mailer - Tool to send SMTP mail
        {5}--Exit
            ''')
        choice5 = input("Enter Your Choice: ")
        if choice5=='1':
            os.system("sudo git clone https://github.com/trustedsec/social-engineer-toolkit.git")
            os.system("sudo apt-get --force-yes -y install git apache2 python-requests libapache2-mod-php \
                        python-pymssql build-essential python-pexpect python-pefile python-crypto python-openssl")
            os.system("cd social-engineer-toolkit && sudo python setup.py install")
        elif choice5=='2':
            print('''sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping
            attacks.
            It requires Python 2.5 or newer, along with the 'twisted' python module.''')
            fff = input("Do You Want To Continue (y/n)")
            if fff=='y' or 'Y':
                os.system("sudo git clone --depth=1 https://github.com/moxie0/sslstrip.git")
                os.system("sudo apt-get install python-twisted-web")
                os.system("sudo python sslstrip/setup.py")
            elif fff=='n' or (N):
                sniffingSpoofing()
            else:
                sniffingSpoofing()
            
        elif choice5=='3':
            os.system("sudo wget http://pastebin.com/raw/DDVqWp4Z --output-document=pisher.py")
            os.system("clear")
            os.system("sudo python2 pisher.py")
        elif choice5=='4':
            os.system("wsudo get http://pastebin.com/raw/Nz1GzWDS --output-document=smtp.py")
            os.system("clear")
            os.system("sudo python2 smtp.py")
        elif choice5=='5':
            print("Good...Bye...See You Later.......")
            time.sleep(4)
            sys.exit()
        else:
            print("Unvalid Choice.....")
            time.sleep(2)
            print("Exiting......")
            sys.exit()          
    except KeyboardInterrupt:
        print("Good...Bye...See You Later.....\n")
        time.sleep(4)
        sys.exit()
def postexploitation():
    print(color.RED + '''  ____           _     _____            _       _ _        _   _             
|  _ \ ___  ___| |_  | ____|_  ___ __ | | ___ (_) |_ __ _| |_(_) ___  _ __  
| |_) / _ \/ __| __| |  _| \ \/ / '_ \| |/ _ \| | __/ _` | __| |/ _ \| '_ \ 
|  __/ (_) \__ \ |_  | |___ >  <| |_) | | (_) | | || (_| | |_| | (_) | | | |
|_|   \___/|___/\__| |_____/_/\_\ .__/|_|\___/|_|\__\__,_|\__|_|\___/|_| |_|
                                |_|                                         
 ''' + color.END)
    print("Post Exploitation Section")
    try:
        print('''
        {1}--Shell Checker
        {2}--POET
        {3}--Phishing Framework
        {4}--Exit
        ''')
        choice6 = input("Enter Your Choice: ")
        if choice6=='1':
            os.system("sudo wget http://pastebin.com/raw/Y0cqkjrj --output-document=ch01.py")
            os.system("clear")
            os.system("sudo python ch01.py")
        elif choice6=='2':
            print("POET is a simple POst-Exploitation Tool.\n")
            os.system("sudo git clone --depth=1 https://github.com/mossberg/poet.git")
            os.system("sudo python poet/server.py")
        elif choice6=='3':
            print("HTTP server for phishing in python. (and framework) Usually you will want to run Weeman with DNS spoof attack. (see dsniff, ettercap).")
            os.system("sudo git clone --depth=1 https://github.com/samyoyo/weeman.git && cd weeman && python weeman.py")
        elif choice6=='4':
            print("Good..Bye....See You Later.....")
            time.sleep(4)
            sys.exit()
        else:
            print("Unvalid Choice...")
            print("Exiting....")
            time.sleep(4)
            sys.exit()
    except KeyboardInterrupt:
        print("Exiting...\n")
        time.sleep(4)
        sys.exit()
