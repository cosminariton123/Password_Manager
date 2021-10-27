from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import base64
import copy


class User():
    def __init__(self, name, parola, seif):
        self.name = name
        self.parola = parola
        self.seif = seif

        if self.seif == '':
            self.seif = dict()

    def adauga_la_seif(self, serviciu, parola):
        
        parola_criptata, iv = encrypt_password(parola, self.parola)
        
        sv = dict()

        sv['parola'] = str(byte_to_string(parola_criptata)) [2:-1]
        sv['iv'] = str(byte_to_string(iv))[2:-1]

        self.seif[serviciu] = sv
        
    
    def sterge_din_seif(self, serviciu):
        del self.seif[serviciu]
    
    def afiseaza_seif(self):
        for key, val in self.seif.items():
            print(key + ': ' + decrypt_password(string_to_byte( val['parola']), self.parola, string_to_byte(val['iv'])))


class Database():
    def __init__(self, file):
        
        self.data = None
        self.user = None
        self.file = file

        fisier = ''

        try:
            with open(self.file, 'r') as f:
                fisier = f.read()
        except FileNotFoundError:
            with open(self.file, "w") as f:
                pass
            with open(self.file, 'r') as f:
                fisier = f.read()
        
        if fisier == '':
            with open(self.file, 'w') as f:
                data = dict()
                data['users'] = list()
                json.dump(data, f, indent = 2)

        with open(self.file, 'r') as f:
            self.data = json.load(f)


    def creare_user(self, username, password):
        
        for person in self.data['users']:
            if person['name'] == username:
                print('Numele deja a fost luat')
                return

        persoana = dict()
        persoana['name'] = username

        salt = os.urandom(32)


        persoana['salt'] = str(byte_to_string(salt))[2:-1]
        persoana['master_password']= encrypt_password_master(password, salt)
        persoana['seif'] = ''
        self.data['users'].append(persoana)
        self.autentificare(username, password)
        self.save()
    
    def stergere_user_curent(self):
        if  self.user == None:
            print("Nu esti autentificat cu un cont!")
        else:
            for idx, person in enumerate(self.data["users"]):
                if person["name"] == self.user.name:
                    del self.data["users"][idx]
            print("Utilizatorul curent, " + self.user.name + ", a fost sters")
            with open(self.file, 'w') as f:
                json.dump(self.data, f, indent = 2)
            self.logout()
    
    def autentificare(self, username, password):
        
        flag = False
        for person in self.data['users']:
            if person['name'] == username:
                
                salt = string_to_byte( person['salt'])

                if person['master_password'] == encrypt_password_master(password, salt):
                    
                    flag = True
                    self.user = User( person['name'], password, person['seif'])
        
        if flag == False:
            print('Autentificare nereusita')


    def logout(self):
        self.user = None

    def afisare_date_user(self):
        if self.user == None:
            print('Nu exista un user autentificat')
            return

        
        print('Nume :' + self.user.name)
        print('')

        self.user.afiseaza_seif()


    def adauga_la_seif(self, serviciu, parola):
        if self.user == None:
            print('Nu exista un user autentificat')
            return
        
        self.user.adauga_la_seif(serviciu, parola)

    def sterge_din_seif(self, serviciu):
        if self.user == None:
            print('Nu exista un user autentificat')
            return
        
        self.user.sterge_din_seif(serviciu)

    def save(self):
        if self.user == None:
            print('Nu exista un user autentificat')
            return
        
        exists = False
        for person in self.data["users"]:
            if person["name"] == self.user.name:
                exists = True
        
        if exists == False:
            self.data['users'].append(copy.deepcopy(self.user))

        for person in self.data['users']:
            if person['name'] == self.user.name:
                person['seif'] = self.user.seif


        with open(self.file, 'w') as f:
            json.dump(self.data, f, indent = 2)

def encrypt_password_master(parola, salt):

    parola = parola.encode('ascii') 
    parola = b''.join([parola,salt])

    digest = hashes.Hash(hashes.SHA3_512())
    digest.update(parola)

    parola_hashed = digest.finalize()
    
    parola_hashed = byte_to_string(parola_hashed)
    return str(parola_hashed)[2:-1]


def encrypt_password(parola, key):

    if len(key) * 8 > 256:
        raise ValueError("key e prea mare")
    
    else:
        
        while len(key) * 8 < 256:
            key += ' '
    
    while len(parola) % 16 != 0:
        parola += ' '


    parola = parola.encode('ascii') 
    key = key.encode('ascii')


    IV = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV))
    encryptor = cipher.encryptor()

    parola_criptata = encryptor.update(parola) + encryptor.finalize()

    return parola_criptata, IV


def decrypt_password(parola, key, IV):

    if len(key) * 8 > 256:
        raise ValueError("key e prea mare")
    
    else:
        
        while len(key) * 8 < 256:
            key += ' '
    key = key.encode('ascii')

    cipher = Cipher(algorithms.AES(key), modes.CBC(IV))
    decryptor = cipher.decryptor()

    parola_decriptata =  decryptor.update(parola) + decryptor.finalize()

    parola_decriptata = parola_decriptata.decode('ascii')
    parola_decriptata = parola_decriptata.rstrip()

    return parola_decriptata
    


def string_to_byte(string):
    
    return_value = base64.b64decode(string)

    return return_value



def byte_to_string(byte):
    
    return_value = base64.b64encode(byte)

    return return_value





if __name__ == '__main__':

    FISIER_BAZA_DE_DATE = 'data.json'

    database = Database(FISIER_BAZA_DE_DATE)

    optiuni_alegere_nelogat = {
                                1:database.creare_user,
                                2:database.autentificare}

    optiuni_alegere_logat = {1:lambda: database.adauga_la_seif(input("Serviciu="), input("Parola=")),
                             2:database.logout,
                             3:database.save,
                             4:database.afisare_date_user,
                             5:lambda: database.stergere_user_curent() if input("Introdu numele contului pentru confirmare: ") == database.user.name else print("Incorect")}



    while True:
        if database.user == None:
            try:
                alegere = int(input("\n1 Creare user\n2 Autentificare\n"))
            except ValueError:
                alegere = None
            if alegere in optiuni_alegere_nelogat:
                optiuni_alegere_nelogat[alegere](input("Username="), input("Password="))
            else:
                print("Optiunea nu exista\n")
        else:
            try:
                alegere = int(input("\n1 Adauga in seif\n2 Logout\n3 Salveaza schimbarile\n4 Afisare date user curent\n5 Sterge contul curent si salveaza schimbarile\n"))
            except ValueError:
                alegere = None
            if alegere in optiuni_alegere_logat:
                optiuni_alegere_logat[alegere]()
            else:
                print("Optiunea nu exista\n")

            

    database.creare_user('Cosmin', 'ParolaExtremDeSigura')
    database.creare_user('Paul', '123456')
    database.creare_user('Alex', 'pisica')
    database.creare_user('Ana', 'parola123')
    
    database.autentificare('Cosmin', 'ParolaExtremDeSigura')
    database.adauga_la_seif('Microsoft', 'parolaMicrosof')
    database.adauga_la_seif('Yahoo', 'parolaYahoo')
    database.adauga_la_seif('Facebook', 'parolaFacebook')
    database.save()
    database.logout()

    database.autentificare('Ana', 'parola123')
    database.adauga_la_seif('tinder', 'parolaTinder')
    database.adauga_la_seif('gmail', 'parolaGmail')
    database.save()
    database.logout()
    


    database.autentificare('Cosmin', 'ParolaExtremDeSigura')
    database.afisare_date_user()
    database.logout()

    print('\n\n\n')
    database.autentificare('Ana', 'parola123')
    database.afisare_date_user()
    database.stergere_user_curent()