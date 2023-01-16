import base64 #per codiificare i dati
from socket import *
from datetime import datetime
from getmac import get_mac_address as gma #per ottenere indirizzi mac
from requests import get #per ottenere l'indrizzo pubblico in Python
from netaddr import IPAddress #per gestire gli indirizzi IP
from Crypto.Cipher import AES
import os as os
import time

ip = get('https://api.ipify.org').text #uno dei metodi per ottenere l'inidirizzo pubblico di un host in Python
S_KEY = '12345678901234567890123456789012' #Chiave simmetrica per la crittografia

#FUNZIONI

#Alcune funzioni utili di supporto alle elaborazioni del server



def pad(byte_array): #Funzione per rendere il testo in chiaro multiplo di 16 byte (come previsto da AES)
    BLOCK_SIZE = 16
    pad_len = BLOCK_SIZE - len(byte_array) % BLOCK_SIZE
    return byte_array + (bytes([pad_len]) * pad_len)


def unpad(byte_array): #Rimuovo il padding alla fine dell'array di byte
    last_byte = byte_array[-1]
    return byte_array[0:-last_byte]

def encryptAES(key, message): #CIFRATURA
    """
    La stringa in input viene restituita come stringa criptata e
    codificata in base64Input

    """

    byte_array = message.encode("UTF-8") #Codifico il messaggio in UTF-8

    padded_palintext = pad(byte_array) #Rendo la stringa multiplo di 16 byte

    #Genero un vettore di inizializzazione random (come nel client)
    iv = os.urandom(AES.block_size)

    """
    Creo un'istanza di un cifrario AES fornendo la chiave (codificata),
    la modalità (cifrario a blocchi con catena, AES.MODE_CBC) e il VI (anche in tal caso,
    il processo è identico a quello fatto sul client JAVA)
    
    """
    cipher = AES.new( key.encode("UTF-8"), AES.MODE_CBC, iv )
    encrypted = cipher.encrypt(padded_palintext)

    """
    Restituisco la stringa, codificata in base64 e decodificata, che contiene il
    vettore di inizializzazione e il messaggio cifrato
    
    """
    return base64.b64encode(iv+encrypted).decode("UTF-8")

def decryptAES(key, message): #DECIFRATURA

    """
    Operazione duale alla cifratura.
    Anche qui, i passaggi sono gli stessi visti sul client Java

    """

    byte_array = base64.b64decode(message) #Decodifico il messaggio

    iv = byte_array[0:16] #Estraggo il IV dal messaggio criptato

    messagebytes = byte_array[16:] #Estraggo il testo cifrato

    # Creo un cifrario (anche in tal caso con la chiave, la modalità e il vettore)
    cipher = AES.new(key.encode("UTF-8"), AES.MODE_CBC, iv )

    decrypted_padded = cipher.decrypt(messagebytes) #Decripto il messaggio

    decrypted = unpad(decrypted_padded) #Rimuovo l'evnetuale padding applicato in fase di cifratura

    return decrypted.decode("UTF-8"); #Ritorno il messaggio decriptato e decodificato



def binaryToDecimal(str_binary): #Conversione da binario in decimale
    int_binary = int(str_binary) #Il parametro della funzione è una stringa, quindi devo convertirla in intero
    decimal, i = 0, 0
    while (int_binary != 0):
        dec = int_binary % 10
        decimal = decimal + dec * pow(2, i)
        int_binary = int_binary // 10
        i += 1
    return str(decimal)

class IPv4Addr: #Classe per gestire e calcolare tutte le informazioni relative all'IP

    """
    ATTRIBUTI DELLA CLASSE

    """

    broadcast_addr = ""
    binary_bcast_address = ""
    net_addr = ""
    binary_net_address = ""
    host_num = 0
    num_of_ids = 0
    wildcard = ""
    binary_addr = ""
    isClassful = False
    netmask = ""
    dotted_deciaml_netmask = ""

    """
    
    COSTRUTTORE DELLA CLASSE
    
    """

    def __init__(self, address, netmaskInSlashNotation):

            self.address = address
            self.str_netmaskInSlashNotation= netmaskInSlashNotation
            self.netmaskInSlashNotation = int (self.str_netmaskInSlashNotation)
            self.calculateBinaryAddr()
            self.calculateAddrClass()
            self.calculateNetMask()
            self.calculateWildcard()
            self.calculateDottedDeciamNetmask()
            self.calculateIDsNumber()
            self.calculateHostNumbers()
            self.calculateNetworkAddr()
            self.calculateBroadcastAddr()

            if self.netmaskInSlashNotation % 8 == 0 and (self.IP_Class == "A" or self.IP_Class == "B" or self.IP_Class == "C"):
                self.isClassful = True


    """
    METODI DELLA CLASSE (utilizzati per calcolare tutti i parametri relativi all'IP_CALC di un IP)
    """

    def calculateAddrClass(self):

        """
        Classe A = indirizzi che iniziano con 0
        Classe B = indirizzi che iniziano con 10
        Classe C = indirizzi che iniziano con 110
        Classe D = indirizzi che iniziano con 1110 (multicast)
        Classe E = indirizzi che iniziano con 1111 (per scopi futuri)
        """

        self.IP_Class = "NON CALCOLATO"

        if self.binary_addr[0] == "0":
            self.IP_Class = "A"
        elif self.binary_addr[0] == "1" and self.binary_addr[1] == "0":
            self.IP_Class = "B"
        elif self.binary_addr[0] == "1" and self.binary_addr[1] == "1" and self.binary_addr[2] == "0":
            self.IP_Class = "C"
        elif self.binary_addr[0] == "1" and self.binary_addr[1] == "1" and self.binary_addr[2] == "1" and self.binary_addr[3] == "0":
            self.IP_Class = "D (Multicast)"
        elif self.binary_addr[0] == "1" and self.binary_addr[1] == "1" and self.binary_addr[2] == "1" and self.binary_addr[3] == "1":
            self.IP_Class = "E (Riservato per usi futuri)"
        else:
            self.IP_Class = " ERROR "
            print("Errore nel calcolare la classe dell'indirizzo IP fornito")

    def calculateNetworkAddr(self):

        bin = self.binary_addr.replace(".", "") #decompongo l'indirizzo nei suoi ottetti
        index = 0
        binary_net_addr = ""
        for i in range(0, self.netmaskInSlashNotation):
            binary_net_addr += bin[index]
            index += 1

        for i in range (self.netmaskInSlashNotation, 32):
            binary_net_addr += "0"
            """
                Per calcolare l'indirizzo della rete setto a 0 tutti i bit
                riservati alla parte host (32 - valore della netmask)
            """

        self.binary_net_address = binary_net_addr
        octects = [self.binary_net_address[i:i + 8] for i in range(0, len(self.binary_net_address), 8)]

        for i in range(len(octects)):
            self.net_addr += binaryToDecimal(int(octects[i]))
            if i < 3:
                self.net_addr += "." #Formatto la stringa della netmask inserendo opportunamente il .

    def calculateBroadcastAddr(self):
        #Segue lo stesso principio per calcolare l'indirizzo di rete ma settando ad 1 tutti i bit per la parte host
        bin = self.binary_addr.replace(".", "")
        index = 0
        binary_bcast_addr = ""
        for i in range(self.netmaskInSlashNotation ):
            binary_bcast_addr += bin[index]
            index += 1

        for i in range(self.netmaskInSlashNotation, 32):
            binary_bcast_addr += "1"


            """
                                    Per calcolare l'indirizzo di broadcast setto a 1 tutti i bit
                                    riservati alla parte host (32 - valore della netmask)
                                    """

        print(binary_bcast_addr)
        octects = [binary_bcast_addr[i:i + 8] for i in range(0, len(binary_bcast_addr), 8)]
        print(octects[0])
        print(octects[1])
        print(octects[2])
        print(octects[3])

        for i in range(4):
            self.broadcast_addr += binaryToDecimal(octects[i])
            if i < 3:
                self.broadcast_addr += "."


    def calculateNetMask(self): #calcolo la netmask in notazione binaria

            for i in range(int(self.netmaskInSlashNotation)):
                self.netmask += "1" #ho tanti "1" di fila quanto il valore della netmask...
            for i in range(32 - int(self.netmaskInSlashNotation)):
                self.netmask +="0" #altrimenti tutti 0

            self.netmask = '.'.join(self.netmask[i:i + 8] for i in range(0, len(self.netmask), 8))

    def calculateWildcard(self): #calcolo la wildcard (complemento della netmask)

        for number in self.netmask:
            if number == "1": #se la netmask = 1 -> wildcar = 0 (e viceversa)
                self.wildcard += "0"
            elif number == "0":
                self.wildcard += "1"
            else:
                print("Errore nel calcolo della wildcard")

        self.wildcard = '.'.join(self.wildcard[i:i + 8] for i in range(0, len(self.wildcard), 8))

    def calculateHostNumbers(self): #calcolo il numero degli host indirizzabili
        self.host_num = self.num_of_ids - 2

    def calculateIDsNumber(self):
        """
        Calcolo il numero degli ID della rete
        (compreso l'indirizzo di broadcast e quello della rete)
        """
        self.num_of_ids = pow(2, 32 - int(self.netmaskInSlashNotation))

    def calculateBinaryAddr(self): #converto l'indirizzo IP fornito in binario

        ip = IPAddress(self.address)
        binary = (ip.bits())
        self.binary_addr = binary

    def calculateDottedDeciamNetmask(self): #converto la netmask fornita in notazione dotted deciaml

        split_netmask = (self.netmask.split('.'))
        for i in range(4):
            self.dotted_deciaml_netmask += binaryToDecimal(split_netmask[i])
            if i < 3:
                self.dotted_deciaml_netmask += "."


    def getAllInfo(self):

        #Combino insieme tutte le informazioni calcolate, le stampo a video e le ritorno all'interno di un dictionary

        address_info = {
                        "Indirizzo da calcolare": self.address,
                        "Indirizzo in binario" : self.binary_addr,
                        "Netmask in notazione /" : str(self.netmaskInSlashNotation),
                        "Maschera di sottorete binaria": self.netmask,
                        "Maschera di sottorete in notazione dotted decimal": str(self.dotted_deciaml_netmask),
                        "Wildcard" : self.wildcard,
                        "Indirizzo di broadcast" : self.broadcast_addr,
                        "Indirizzo della sottorete": self.net_addr,
                        "Numero di host indirizzabili": str(self.host_num),
                        "Numero di ID della sottorete":str(self.num_of_ids),
                        "Classful": str(self.isClassful)

                        }
        if int(self.netmaskInSlashNotation) == 30: #caso particolare netmask
            optional_info = {"Altro: ": "Point-to-point link"}
            address_info.update(optional_info)


        #STAMPO A VIDEO I CALCOLI FATTI SULL'IP

        print("\n ---------------------- IP CALC INFO ---------------------")
        print("IP ADDRESS DA CALCOLARE: " + self.address + " | BINARIO: " + self.binary_addr)
        print("NETMASK: " + self.netmask + " | "  + "(/" + str(self.netmaskInSlashNotation) + ")" + " | " + self.dotted_deciaml_netmask)
        print("WILDCARD: " + self.wildcard)
        print("CLASSE DI INDIRIZZAMENTO: " + self.IP_Class + "| L'INDIRIZZO E' CLASSFUL: " + str(self.isClassful))
        print("INDIRIZZO DELLA SUBNET: " + self.net_addr)
        print("INDIRIZZO DI BROADCAST: " + self.broadcast_addr)
        print("NUMERO ID DELLA RETE: " + str(self.num_of_ids) + " | NUMERO HOST ASSEGNABILI NELLA RETE: " + str(self.host_num))
        print("__________________________________________________________________\n")
        return address_info

    #FINE CLASSE

def validate(ipaddr, netmask): #verifico se l'utente ha inviato una richiesta corretta

    request_validity = True

    if len(ipaddr) > 32:
       return False

    octecs = ipaddr.split(".")
    if len(octecs)!=4:
        return False

    for octec in octecs:
        if octec.isnumeric() == False:
            return False

    for octect in octecs:
        if int(octect) > 255 or int(octect) < 0:
            return False

    if netmask.isnumeric() == False:
        return False

    if int(netmask) > 30 or int(netmask) < 1:
        return False

    return request_validity

def get_link_local_addr(mac):
    '''
        Si può ottenere l'indirizzo link_local di ipv6 a partire dal mac address
        della schede di rete, utilizzando la tecnica EUI-64.
        Possiamo eseguire questa operazione in 3 passi:
        1) Invertire l'universal/local bit (settimo bel del primo ottetto)
        2) Inserire la sequenza ff:fe in mezzo al mac address
        3) Convertire l' indirizzo ip, con in testa la sequenza fe80::
        - Se trovo una sequenza di 0 posso usare la notazione ::
    '''

    splitted_mac = mac.strip("\n").split(":") #Decompngo il MAC nei suoi ottetti

    #Inverto  l'universal/local bit
    splitted_mac[0] = hex(int(splitted_mac[0], 16) ^ 2)[2:]

    #Inserisco ff:fe in mezzo al MAC address (ottengo quindi l'EUI)
    part1 = splitted_mac[0] + splitted_mac[1] + ":"
    part2 = splitted_mac[2] + "ff" + ":"
    part3 = "fe" + splitted_mac[3] + ":"
    part4 = splitted_mac[4] + splitted_mac[5]

    #Aggiungo fe80:: e metto insieme le varie parti
    return "fe80::" + part1.lstrip("0") + part2.lstrip("0") + part3.lstrip("0") + part4.lstrip("0")



print("---- AVVIO DEL SERVER ---- PROTOCOLLO DI TRASPORTO: TCP\n")


portNumber = 12000 #port number well known del server su cui ascolterà le richieste da parte dei CLIENT
serverSocket = socket(AF_INET, SOCK_STREAM)#protocollo TCP, se volessi usare UDP dovrei scrivere SOCK_DATAGRAM come secondo parametro della socket
serverSocket.bind(('', portNumber))
serverSocket.listen()
"""
il numero tra parentesi nella liste() 
indica il numero massimo di client, se non speficiato viene ragionevolmente scelto dal SO 

"""

iterations = 0

while (1): #CICLO PRINCIPALE

    iterations +=1
    """
    Qui ottengo alcune informazioni sulla macchina server
    """

    public_ip = get('https://api.ipify.org').text
    hostname = gethostname()
    ip_address = gethostbyname(hostname)
    mac = gma()
    ipv6_address = get_link_local_addr(mac)

    print("========== INFORMAZIONI SULLA MACCHINA SERVER ========== ")
    print("HOST NAME: " + hostname)
    print("CON IPv4: " + ip_address)
    print("CON INDIRIZZO LINK-LOCAL IPV6: " + ipv6_address)
    print("CON MAC: " + mac)
    print("IP PUBBLICO: " + public_ip)
    print("IN ASCOLTO SULLA PORTA: " + str(portNumber))
    print("============================================================\n")


    print(">>> SERVER IN ATTESA DI UN CLIENT. [Iterazione numero: " + str(iterations) + " ] <<<")


    # -------------- GESTIONE CONNESSIONE -----------------------------

    connectionSocket, client_addr = serverSocket.accept()  #accetto la connessione con il client
    #client_addr contiene sia l'ip del client che la porta sorgente
    print("CONNESSIONE ACCETTATA CON IL CLIENT AVENTE INDIRIZZO: " + str(client_addr[0]) +
          " IN COMUNICAZIONE SULLA PORTA: " + str(client_addr[1]))

    print("\n ========== QUINTUPLA IDENTIFICATIVA DEL FLUSSO ==========\n")
    print("SERVER IP: " + str(ip_address) + " | PORTA DEL SERVER: " + str(portNumber) + " | IP CLIENT: "
        + str(client_addr[0]) +" | PORTA CLIENT: " + str(client_addr[1]) + "| PROTOCOLLO: " + str(serverSocket.type))

    print("==================================================")

    msg = connectionSocket.recv(4096).decode()
    # la .recv() mi consente di estrarre i dati inviati dal mittente

    now = datetime.now()
    serverDateAndTime = now.strftime("%d/%m/%Y %H:%M:%S")

    print("MESSAGGIO CRITTOGRAFATO RICEVUTO DAL CLIENT: " + str(client_addr[0]) + " IN DATA " + str(serverDateAndTime))
    print(msg)

    dec_msg = decryptAES(S_KEY,msg.encode("utf-8")) #decripto il messaggio inviato del client
    print("MESSAGGIO DECIFRATO: ")
    print(dec_msg)

    client_request = dec_msg.split(" ")

    """
    la richiesta del client è composta da 2 parti, opportunamente separate
    da un carattere vuoto. La prima parte indica l'ip di cui si richiede l'IP_CALC
    e la seconda la netmask
    """
    response_msg = ""
    address_to_process = client_request[0]


    if len(client_request) <= 1:
        netmask_to_process = "24"
        response_msg = "Nessuna netmask fornita, verrà applicata quella di defualt (/24)"
    else:
        netmask_to_process = client_request[1]



    print("IL CLIENT HA RICHIESTO L'IP CALC DELL'INDIRIZZO: " + str(address_to_process) +
          " AVENTE NETMASK DEL TIPO /" + str(netmask_to_process))


    if validate(address_to_process, netmask_to_process):

        print("FORMATO INDIRIZZO IP E NETMASK VALIDE. IL SERVER STA PROCEDENDO ALL'ELABORAZIONE DELLA RICHIESTA")

        """
        Se la richiesta è nel formato giusto il server procede ad elaborarla, passando
        i valori di netmask e ip ad un oggetto di classe IPv4Addr
        """
        request_to_elaborate = IPv4Addr(address_to_process, netmask_to_process)
        response_msg += str(request_to_elaborate.getAllInfo())
        #con getAllInfo() memorizzo i dati nella variabile response_msg

    else:
        #Se la richieste è nel formato sbagliato il server risponde con un messaggio di errore
        print("Errore di formattazione nella richiesta del client")
        response_msg += "Formato dell'indirizzo IP o della NETMASK non valido. Inserire un altro valore"


    #----------- COSTRUZIONE MESSAGGIO DI RISPOSTA -----

    now = datetime.now()
    serverResponseTime = now.strftime("%d/%m/%Y %H:%M:%S")
    msg_to_send = "[ Date: " + serverResponseTime + " ]" + " " + response_msg

    print("\n=========================== MESSAGGIO DA INVIARE (PLAINTEXT) =====================\n")
    print(msg_to_send)
    print("=======================================================================================\n")



    encrypted_msg = encryptAES(S_KEY, msg_to_send) #cripto il messaggio da inviare

    print("\n=========================== MESSAGGIO DA INVIARE CRIPTATO =====================\n")
    print(encrypted_msg)
    print("=======================================================================================\n")

    connectionSocket.send(encrypted_msg.encode()) #invio messaggio

    print("\n CHIUSURA CONNESSIONE...\n")
    connectionSocket.close() #abbattimento della connessione
    print("\n CONNESSIONE CHIUSA\n")

# FINE