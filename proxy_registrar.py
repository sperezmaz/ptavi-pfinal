#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Cliente UA que inicia sesion y la cierra con un BYE."""

import sys
import socket
import socketserver
import os
import json
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time
import hashlib
import random

class XMLProxyHandler(ContentHandler):

    def __init__ (self):
        """Constructor. Inicializamos las variables."""
        self.variable = {}
            
    def startElement(self, name, atribs):
        """Método que se llama cuando se abre una etiqueta."""
        tags = {'server': {'name', 'ip', 'puerto'},
                'database': {'path', 'passwdpath'},
                'log': {'path'}}
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
        
class SIPHandler(socketserver.DatagramRequestHandler):
    """SIP class."""

    dicc_users = {}

    def handle(self):
        """handle method of the proxy class."""
        
        line = self.rfile.read()
        print(line.decode('utf-8'))
        message = line.decode('utf-8').split()
        metodo = message[0]
        self.json2registered()
        
        ip_client = self.client_address[0]
        puerto_clnt = self.client_address[1]

        t = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() + 3600))
        
        self.eliminar_usuario(t)                      

        if metodo == "REGISTER":
            sip_address = message[1][4:]
            usuario = sip_address.split(":")[0]
            puerto_client = sip_address.split(":")[1]
            
            if int(message[4].split('/')[0]) >= 0:
                time_exp = int(message[4].split('/')[0])
            else:
                time_exp = 0
                
            t_tot = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(
                                  time.time() + 3600 + time_exp))
            if usuario not in self.dicc_users:
                nonce = str(random.randint(00000000000000000000,
                                       99999999999999999999))
                self.dicc_users[usuario] = {'autorizado': False,
                                            'address': ip_client,
                                            'expires': t_tot,
                                            'port': puerto_client, 
                                            'nonce': nonce}
                self.wfile.write(bytes(('SIP/2.0 401 Unauthorized\r\n' + 
                                 'WWW-Authenticate: Digest nonce="' +
                                 nonce + '"\r\n\r\n'), 'utf-8'))
                                 
            elif not self.dicc_users[usuario]['autorizado']:
                contra = obtener_contra(usuario)
                nonce = self.dicc_users[usuario]['nonce']
                h = hashlib.md5()
                h.update(bytes(contra, 'utf-8') + bytes(nonce, 'utf-8'))
                response = h.hexdigest()
                
                try:
                    authenticate_recib = message[7].split('"')[1]
                except IndexError:
                    authenticate_recib = ""
                    
                if authenticate_recib == response:
                    self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
                    self.dicc_users[usuario]['autorizado'] = True
                    self.dicc_users[usuario]['expires'] = t_tot
                else:
                    self.wfile.write(bytes(('SIP/2.0 401 Unauthorized\r\n' + 
                                     'WWW-Authenticate: Digest nonce="' +
                                     nonce + '"\r\n\r\n'), 'utf-8'))
            else:
                self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")            
     
            self.register2json()                  


    def register2json(self):
        """Imprime en fichero informacion sobre el usuario."""
        json.dump(self.dicc_users, open(DATABASE, 'w'), indent=4)

    def json2registered(self):
        """Leer contenido y usarlo para usuarios registrados."""
        try:
            with open(DATABASE) as in_file:
                self.dicc_users = json.load(in_file)
        except:
            self.dicc_users = {}
            
    def eliminar_usuario(self, t):
        """Borra los usuarios expirados."""
        expirados = []
        for usuari in self.dicc_users:
            if self.dicc_users[usuari]['expires'] <= t:
                expirados.append(usuari)
        for usua_exp in expirados:
            del self.dicc_users[usua_exp]
                

def obtener_contra(usuario):
    """Busca contraseña en archivo passwords."""
    try:
        file = open(datos['database']['passwdpath'], "r")
        lines = file.readlines()
        password = "admin"
        for line in lines:
            user_line = line.split()[0].split(":")[0]
            if usuario == user_line:
                password = line.split()[0].split(":")[1]
    except:
        password = "admin"
    return password        


if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit("Usage: python3 proxy_registrar.py config")
        
    parser = make_parser()
    cHandler = XMLProxyHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    # print(cHandler.get_tags())
    datos = cHandler.get_tags()
    DATABASE = datos['database']['path']
    IP = datos['server']['ip']
    PUERTO = datos['server']['puerto']
    print(PUERTO)
    serv = socketserver.UDPServer((IP, int(PUERTO)), SIPHandler)
    print("Lanzando servidor UDP de eco...")
    try:
        serv.serve_forever()  # espera en un bucle
    except KeyboardInterrupt:  # ^C
        print("Finalizado servidor")       
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
