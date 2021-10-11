import sys
import time
import os
import script
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
def main():
    os.system("clear")
    toollogo = '''     _    _     ___   _  _     _   _            _    
   / \  | |   |_ _| | || |   | | | | __ _  ___| | __
  / _ \ | |    | |  | || |_  | |_| |/ _` |/ __| |/ /
 / ___ \| |___ | |  |__   _| |  _  | (_| | (__|   < 
/_/   \_\_____|___|    |_|   |_| |_|\__,_|\___|_|\_\
                                                    
 '''
    print (toollogo + color.RED + '''
       }--------------{+} Coded By Ali Belalia  {+}--------------{
       }--------{+}  GitHub.com/alibelalia/ali4hack  {+}--------{
    ''' + color.END)
    try:
        print(''''
        {1} Information Gathering
        {2} Password Attack
        {3} Wireless Tools
        {4} Exploitation Tools
        {5} Sniffing & Spoofing
        {6} Post Exploitation
        {99} Exit ''')
        ch = input("Enter Your Choice: ")
        if ch=='1':
            script.info()
        elif ch=='2':
            script.passattack()
        elif ch=='3':
            script.wireless()
        elif ch=='4':
            script.expl()
        elif ch=='5':
            script.sniffingSpoofing()
        elif ch=='6':
            script.postexploitation()
        elif ch=='9':
            print("Exiting....")
            time.slp(3)
            sys.exit()
        else:
            os.system("clear")
            sys.exit()
    except KeyboardInterrupt:
        print("\nGood...Bye....")
        time.sleep(3)
        sys.exit()
main()
