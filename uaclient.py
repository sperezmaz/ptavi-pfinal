#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Cliente UA que inicia sesion y la cierra con un BYE."""

import sys
import socket
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

if __name__ == "__main__":
    # Constantes. Dirección IP del servidor y contenido a enviar
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
    # Creamos el socket, lo configuramos y lo atamos a un servidor/puerto
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
        my_socket.connect((proxy_ip, int(proxy_port)))

        #if METODO not in ["REGISTER", "INVITE", "BYE"]:
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
            print('Received --', data.decode('utf-8'))
    print("Socket terminado.")
