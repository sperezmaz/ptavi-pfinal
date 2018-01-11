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
from uaclient import log


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
        print('Recibido -- ', line.decode('utf-8'))
        message = line.decode('utf-8').split()
        metodo = message[0]
        self.json2registered()

        ip_client = str(self.client_address[0])
        puerto_client = str(self.client_address[1])

        t = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() + 3600))

        self.eliminar_usuario(t)                      

        if metodo == "REGISTER":
            sip_address = message[1][4:]
            usuario = sip_address.split(":")[0]
            puerto_serv = sip_address.split(":")[1]

            evento = "Received from "
            mensaje = line.decode('utf-8').replace("\r\n", " ")
            log(rutalog, evento, ip_client, puerto_client, mensaje)

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
                                            'port': puerto_serv, 
                                            'nonce': nonce}
                line = 'SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest'
                line += ' nonce="' + nonce + '"\r\n\r\n'
                print("Enviando -- ", line)
                self.wfile.write(bytes(line, 'utf-8'))

            elif not self.dicc_users[usuario]['autorizado']:
                contra = obtener_contra(usuario)
                nonce = self.dicc_users[usuario]['nonce']
                h = hashlib.md5()
                h.update(bytes(contra, 'utf-8') + bytes(nonce, 'utf-8'))
                response = h.hexdigest()

                try:
                    authenticate_recib = message[7].split('"')[1]
                except:
                    authenticate_recib = ""
                    line = "Failed to get the password"
                    print(line)
                    evento = "Error"
                    log(rutalog, evento, proxy_ip, proxy_port, line)

                if authenticate_recib == response:
                    line = "SIP/2.0 200 OK\r\n\r\n"
                    print("Enviando -- ", line)
                    self.wfile.write(bytes(line, 'utf-8'))

                    self.dicc_users[usuario]['autorizado'] = True
                    self.dicc_users[usuario]['expires'] = t_tot
                else:
                    line = 'SIP/2.0 401 Unauthorized\r\nWWW-Authenticate:'
                    line += ' Digest nonce="' + nonce + '"\r\n\r\n'
                    print("Enviando -- ", line)
                    self.wfile.write(bytes(line, 'utf-8'))

            else:
                expires_anterior = self.dicc_users[usuario]['expires']
                if t_tot >= expires_anterior:
                    self.dicc_users[usuario]['expires'] = t_tot
                line = "SIP/2.0 200 OK\r\n\r\n"
                print("Enviando -- ", line)
                self.wfile.write(bytes(line, 'utf-8'))

            evento = "Sent to "
            mensaje = line.replace("\r\n", " ")
            log(rutalog, evento, ip_client, puerto_client, mensaje)

            self.register2json()

        elif metodo == "INVITE":

            evento = "Received from "
            mensaje = line.decode('utf-8').replace("\r\n", " ")
            log(rutalog, evento, ip_client, puerto_client, mensaje)

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
                try:
                    address_destino = message[1][4:]
                    ip_destino = self.dicc_users[address_destino]['address']
                    puerto_destino = self.dicc_users[address_destino]['port']
                    my_socket.connect((ip_destino, int(puerto_destino)))
                    my_socket.send(bytes(line.decode('utf-8'), 'utf-8'))
                    print("Enviando -- ", line.decode('utf-8'))

                    evento = "Sent to "
                    mensaje = line.decode('utf-8').replace("\r\n", " ")
                    log(rutalog, evento, ip_destino, puerto_destino, mensaje)

                    data = my_socket.recv(1024)
                    data = data.decode('utf-8')
                    print("Recibido -- ", data)

                    evento = "Received from "
                    mensaje = data.replace("\r\n", " ")
                    log(rutalog, evento, ip_destino, puerto_destino, mensaje)

                    self.wfile.write(bytes(data, 'utf-8'))

                except:
                    print("User " + address_destino + " Not Found")
                    data = "SIP/2.0 404 User Not Found\r\n\r\n"
                    self.wfile.write(bytes(data, 'utf-8'))

                evento = "Sent to "
                mensaje = data.replace("\r\n", " ")
                log(rutalog, evento, ip_client, puerto_client, mensaje)

        elif metodo == "ACK":

            evento = "Received from "
            mensaje = line.decode('utf-8').replace("\r\n", " ")
            log(rutalog, evento, ip_client, puerto_client, mensaje)

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
                address_destino = message[1][4:]
                ip_destino = self.dicc_users[address_destino]['address']
                puerto_destino = self.dicc_users[address_destino]['port']
                my_socket.connect((ip_destino, int(puerto_destino)))
                my_socket.send(bytes(line.decode('utf-8'), 'utf-8'))
                print("Enviando -- ", line.decode('utf-8'))

                evento = "Sent to "
                mensaje = line.decode('utf-8').replace("\r\n", " ")
                log(rutalog, evento, ip_destino, puerto_destino, mensaje)

        elif metodo == "BYE":
            evento = "Received from "
            mensaje = line.decode('utf-8').replace("\r\n", " ")
            log(rutalog, evento, ip_client, puerto_client, mensaje)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
                try:
                    address_destino = message[1][4:]
                    ip_destino = self.dicc_users[address_destino]['address']
                    puerto_destino = self.dicc_users[address_destino]['port']
                    my_socket.connect((ip_destino, int(puerto_destino)))
                    my_socket.send(bytes(line.decode('utf-8'), 'utf-8'))
                    print("Enviando -- ", line.decode('utf-8'))

                    evento = "Sent to "
                    mensaje = line.decode('utf-8').replace("\r\n", " ")
                    log(rutalog, evento, ip_destino, puerto_destino, mensaje)

                    data = my_socket.recv(1024)
                    data = data.decode('utf-8')
                    print("Recibido -- ", data)

                    evento = "Received from "
                    mensaje = data.replace("\r\n", " ")
                    log(rutalog, evento, ip_destino, puerto_destino, mensaje)

                    line = data
                    self.wfile.write(bytes(line, 'utf-8'))

                except:
                    data = ""
                    print("User " + address_destino + " Not Found")
                    line = "SIP/2.0 404 User Not Found\r\n\r\n"
                    self.wfile.write(bytes(line, 'utf-8'))

                print("Enviando -- ", line)

                evento = "Sent to "
                mensaje = line.replace("\r\n", " ")
                log(rutalog, evento, ip_client, puerto_client, mensaje)

        elif metodo not in ["REGISTER", "INVITE", "ACK", "BYE"]:
            line = "SIP/2.0 405 Method Not Allowed\r\n\r\n"
            print("Enviando -- ", line)
            self.wfile.write(bytes(line, 'utf-8'))

            evento = "Sent to "
            mensaje = line.replace("\r\n", " ")
            log(rutalog, evento, ip_client, puerto_client, mensaje)

        else:
            line = "SIP/2.0 400 Bad Request\r\n\r\n"
            print("Enviando -- ", line)
            self.wfile.write(bytes(line, 'utf-8'))

            evento = "Sent to "
            mensaje = line.replace("\r\n", " ")
            log(rutalog, evento, ip_client, puerto_client, mensaje)

    def register2json(self):
        """Imprime en fichero informacion sobre el usuario."""
        json.dump(self.dicc_users, open(database, 'w'), indent=4)

    def json2registered(self):
        """Leer contenido y usarlo para usuarios registrados."""
        try:
            with open(database) as in_file:
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

    datos = cHandler.get_tags()
    database = datos['database']['path']
    rutalog = datos['log']['path']
    ip_serv = datos['server']['ip']
    puerto_serv = datos['server']['puerto']
    evento = ""
    serv = socketserver.UDPServer((ip_serv, int(puerto_serv)), SIPHandler)
    log(rutalog, evento, ip_serv, puerto_serv, "Starting...")
    print("Lanzando servidor UDP de eco...")
    try:
        serv.serve_forever()  # espera en un bucle
    except KeyboardInterrupt:  # ^C
        log(rutalog, evento, ip_serv, puerto_serv, "Finishing.")
        print("Finalizado servidor")
