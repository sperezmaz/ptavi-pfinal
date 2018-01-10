#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Cliente UA que inicia sesion y la cierra con un BYE."""

import sys
import socket
import threading
from os import system
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time
import hashlib


class XMLHandler(ContentHandler):

    def __init__ (self):
        """Constructor. Inicializamos las variables"""
        self.variable = {}

    def startElement(self, name, atribs):
        """Método que se llama cuando se abre una etiqueta"""
        tags = {'account': {'username', 'passwd'},
                'uaserver': {'ip', 'puerto'},
                'rtpaudio': {'puerto'},
                'regproxy': {'ip', 'puerto'},
                'log': {'path'},
                'audio': {'path'}}
        atribcont = {}

        if name in tags:

            for atribute in tags[name]:
                if name == 'uaserver' and atribute == 'ip' \
                    and atribs.get(atribute, "127.0.0.1") != "":
                    atribcont[atribute] = atribs.get(atribute, "127.0.0.1")
                else:
                    if atribs.get(atribute, "") != "":
                        atribcont[atribute] = atribs.get(atribute, "")

            self.variable[name] = atribcont

    def get_tags(self):
        return self.variable

def viartp(ip_server, puert_rtp, fichero_audio):
    """Hilo para rtp."""
    aEjec = "./mp32rtp -i " + ip_server + " -p " + puert_rtp
    aEjec += " < " + fichero_audio
    print("Vamos a ejecutar --", aEjec)
    system(aEjec)

def vlc(ip_rtp, port_rtpvlc):
    """Thread for cvlc playback."""
    vlc = "cvlc rtp://@" + ip_rtp + ":" + port_rtpvlc + " 2> " + "/dev/null &"
    print("Vamos a ejecutar", vlc)
    system(vlc)

if __name__ == "__main__":

    try:
        CONFIG = sys.argv[1]
        METODO = sys.argv[2].upper()
        if METODO == "REGISTER":
            OPCION = int(sys.argv[3])
        else:
            OPCION = sys.argv[3]
    except:
        sys.exit("Usage: python uaclient.py config method option")

    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    # print(cHandler.get_tags())
    datos = cHandler.get_tags()

    proxy_ip = datos["regproxy"]["ip"]
    proxy_port = datos['regproxy']['puerto']
    name = datos["account"]["username"]
    puert_serv = datos["uaserver"]["puerto"]
    ip_server = datos["uaserver"]["ip"]
    contra = datos["account"]["passwd"]
    puert_rtp = datos['rtpaudio']['puerto']
    fichero_audio = datos['audio']['path']

    # Creamos el socket, lo configuramos y lo atamos a un servidor/puerto
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.connect((proxy_ip, int(proxy_port)))

        if METODO == "REGISTER":
            line1 = METODO + " sip:" + name + ':' + puert_serv + ' SIP/2.0\r\n'
            line = line1 + "Expires: " + str(OPCION) + "\r\n\r\n"

            print("Enviando -- ", line)
            my_socket.send(bytes(line, 'utf-8'))  # lo pasamos a bytes

            data = my_socket.recv(1024)
            
            if "401" in data.decode('utf-8').split():
                print('Recibido -- ', data.decode('utf-8'))
                nonce_recib = data.decode('utf-8').split()[-1].split('"')[1]
                h = hashlib.md5()
                h.update(bytes(contra, 'utf-8') + bytes(nonce_recib, 'utf-8'))
                response = h.hexdigest()

                line2 = 'Authorization: Digest response="' + response
                line2 += '"\r\n\r\n'
                line = line1 + "Expires: " + str(OPCION) + "\r\n" + line2
                print("Enviando -- ", line)
                my_socket.send(bytes(line, 'utf-8'))
                data = my_socket.recv(1024)
                print('Recibido -- ', data.decode('utf-8'))
            else:
                print('Recibido -- ', data.decode('utf-8'))

        elif METODO == "INVITE":

            line = METODO + " sip:" + OPCION + " SIP/2.0\r\n"
            line += "Content-Type: application/sdp\r\n\r\nv=0\r\no=" + name
            line += " " + ip_server + "\r\n" + "s=lasesion\r\nt=0\r\nm=audio " 
            line += puert_rtp + " RTP\r\n\r\n"
            print("Enviando -- ", line)
            my_socket.send(bytes(line, 'utf-8'))

            data = my_socket.recv(1024)
            data = data.decode('utf-8')
            print('Recibido -- ', data)
            correcto = "SIP/2.0 100 Trying\r\n\r\n" 
            correcto += "SIP/2.0 180 Ringing\r\n\r\n" + "SIP/2.0 200 OK\r\n"
            recibido = data.split("Content")[0]
            if recibido == correcto:
                line = 'ACK sip:' + OPCION + ' SIP/2.0\r\n\r\n'
                my_socket.send(bytes(line, 'utf-8'))
                print("Enviando -- ", line)
                ip_rtp_dest = data.split()[13]
                port_rtp_dest = data.split('m=audio ')[1].split()[0]
                hilo1 = threading.Thread(target=viartp, args=(ip_rtp_dest, 
                                         port_rtp_dest, fichero_audio,))
                hilo2 = threading.Thread(target=vlc, args=(ip_server, 
                                         puert_rtp,))
                hilo1.start()
                hilo2.start()

        elif METODO == "BYE":
            line = METODO + " sip:" + OPCION + " SIP/2.0\r\n\r\n"
            system("killall vlc 2> /dev/null")
            system("killall mp32rtp 2> /dev/null")

            print("Enviando -- ", line)
            my_socket.send(bytes(line, 'utf-8'))

            data = my_socket.recv(1024)
            data = data.decode('utf-8')
            print('Recibido -- ', data)

        elif METODO not in ["REGISTER", "INVITE", "BYE"]:
            line = METODO + " sip:" + name + ":" + puert_serv
            line += " SIP/2.0\r\n\r\n"
            print("Enviando -- ", line)
            my_socket.send(bytes(line, 'utf-8'))

            data = my_socket.recv(1024)
            data = data.decode('utf-8')
            print('Recibido -- ', data)

    print("Socket terminado.")
    
    
    
    
    
    
    
    
    
    
    
    
