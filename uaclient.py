#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Cliente UA que inicia sesion, solicita RTP y cierra sesion con un BYE."""

import sys
import socket
import threading
from os import system
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
import time
import hashlib


class XMLClientHandler(ContentHandler):
    """Maneador XML del UA cliente."""

    def __init__(self):
        """Constructor. Inicializamos las variables."""
        self.variable = {}

    def startElement(self, name, atribs):
        """Metodo que se llama cuando se abre una etiqueta."""
        tags = {'account': {'username', 'passwd'},
                'uaserver': {'ip', 'puerto'},
                'rtpaudio': {'puerto'},
                'regproxy': {'ip', 'puerto'},
                'log': {'path'},
                'audio': {'path'}}
        atribcont = {}

        if name in tags:
            for atribute in tags[name]:
                if name == 'uaserver' and atribute == 'ip':
                    atribcont['ip'] = atribs.get('ip', "127.0.0.1")
                else:
                    if atribs.get(atribute, "") != "":
                        atribcont[atribute] = atribs.get(atribute, "")

            self.variable[name] = atribcont

    def get_tags(self):
        """Funcion para obtener las etiquetas."""
        return self.variable


def viartp(receptor_ip, receptor_puerto, fichero_audio):
    """Hilo para rtp."""
    aEjecutar = "./mp32rtp -i " + receptor_ip + " -p " + receptor_puerto
    aEjecutar += " < " + fichero_audio
    print("Vamos a ejecutar --", aEjecutar)
    system(aEjecutar)


def vlc(ip_rtp, puert_rtpvlc):
    """Hilo para cvlc."""
    vlc = "cvlc rtp://@" + ip_rtp + ":" + puert_rtpvlc + " 2> " + "/dev/null &"
    print("Vamos a ejecutar", vlc)
    system(vlc)


def log(rutafichero, evento, ip, puerto, mensaje):
    """Funcion para escribir en fichero log."""
    with open(rutafichero, 'a') as ficherolog:
        timeformat = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()))
        if evento in ["Sent to ", "Received from "]:
            line = timeformat + " " + evento + ip + ":" + puerto + ": "
            line += mensaje + "\r\n"
        elif mensaje == "Starting...":
            line = "\r\n" + timeformat + " " + mensaje + "\r\n"
        elif mensaje == "Finishing.":
            line = timeformat + " " + mensaje + "\r\n\r\n"
        else:
            line = timeformat + " " + evento + ": " + mensaje + "\r\n"
        ficherolog.write(line)

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
    cHandler = XMLClientHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    datos = cHandler.get_tags()

    proxy_ip = datos["regproxy"]["ip"]
    proxy_port = datos['regproxy']['puerto']
    name = datos["account"]["username"]
    puert_serv = datos["uaserver"]["puerto"]
    ip_server = datos["uaserver"]["ip"]
    cntra = datos["account"]["passwd"]
    puert_rtp = datos['rtpaudio']['puerto']
    fichero_audio = datos['audio']['path']
    rutalog = datos['log']['path']
    evento = ""

    try:
        # Creamos el socket, lo configuramos y lo atamos a un servidor/puerto
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.connect((proxy_ip, int(proxy_port)))

            log(rutalog, evento, proxy_ip, proxy_port, "Starting...")

            if METODO == "REGISTER":
                line = METODO + " sip:" + name + ":" + puert_serv
                line += " SIP/2.0\r\nExpires: " + str(OPCION) + "\r\n\r\n"

                print("Enviando -- ", line)
                my_socket.send(bytes(line, 'utf-8'))  # lo pasamos a bytes

                evento = "Sent to "
                mensaje = line.replace("\r\n", " ")

                data = my_socket.recv(1024)
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                if "401" in data.decode('utf-8').split():
                    nonce_rec = data.decode('utf-8').split()[-1].split('"')[1]
                    print('Recibido -- ', data.decode('utf-8'))

                    evento = "Received from "
                    mensaje = data.decode('utf-8').replace("\r\n", " ")
                    log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                    h = hashlib.md5()
                    h.update(bytes(cntra, 'utf-8') + bytes(nonce_rec, 'utf-8'))
                    response = h.hexdigest()

                    line = METODO + " sip:" + name + ":" + puert_serv
                    line += " SIP/2.0\r\nExpires: " + str(OPCION) + "\r\n"
                    line += 'Authorization: Digest response="' + response
                    line += '"\r\n\r\n'
                    print("Enviando -- ", line)
                    my_socket.send(bytes(line, 'utf-8'))

                    evento = "Sent to "
                    mensaje = line.replace("\r\n", " ")
                    log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                    data = my_socket.recv(1024)
                    print('Recibido -- ', data.decode('utf-8'))
                else:
                    print('Recibido -- ', data.decode('utf-8'))

                evento = "Received from "
                mensaje = data.decode('utf-8').replace("\r\n", " ")
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

            elif METODO == "INVITE":

                line = METODO + " sip:" + OPCION + " SIP/2.0\r\n"
                line += "Content-Type: application/sdp\r\n\r\nv=0\r\no=" + name
                line += " " + ip_server + "\r\n"
                line += "s=lasesion\r\nt=0\r\nm=audio " + puert_rtp
                line += " RTP\r\n\r\n"
                print("Enviando -- ", line)
                my_socket.send(bytes(line, 'utf-8'))

                evento = "Sent to "
                mensaje = line.replace("\r\n", " ")
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                data = my_socket.recv(1024)
                data = data.decode('utf-8')
                print('Recibido -- ', data)

                evento = "Received from "
                mensaje = data.replace("\r\n", " ")
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                correcto = "SIP/2.0 100 Trying\r\n\r\n"
                correcto += "SIP/2.0 180 Ringing\r\n\r\nSIP/2.0 200 OK\r\n"
                recibido = data.split("Content")[0]
                if recibido == correcto:
                    line = 'ACK sip:' + OPCION + ' SIP/2.0\r\n\r\n'
                    my_socket.send(bytes(line, 'utf-8'))
                    print("Enviando -- ", line)

                    evento = "Sent to "
                    mensaje = line.replace("\r\n", " ")
                    log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                    ip_rtp_dest = data.split()[13]
                    port_rtp_dest = data.split('m=audio ')[1].split()[0]

                    mensaje = "RTP"
                    log(rutalog, evento, ip_rtp_dest, port_rtp_dest, mensaje)

                    hilo1 = threading.Thread(target=viartp, args=(ip_rtp_dest,
                                             port_rtp_dest, fichero_audio,))
                    hilo2 = threading.Thread(target=vlc, args=(ip_server,
                                             puert_rtp,))
                    hilo2.start()
                    hilo1.start()

            elif METODO == "BYE":
                line = METODO + " sip:" + OPCION + " SIP/2.0\r\n\r\n"
                system("killall vlc 2> /dev/null")
                system("killall mp32rtp 2> /dev/null")

                print("Enviando -- ", line)
                my_socket.send(bytes(line, 'utf-8'))

                evento = "Sent to "
                mensaje = line.replace("\r\n", " ")
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                data = my_socket.recv(1024)
                data = data.decode('utf-8')
                print('Recibido -- ', data)

                evento = "Received from "
                mensaje = data.replace("\r\n", " ")
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

            elif METODO not in ["REGISTER", "INVITE", "BYE"]:
                line = METODO + " sip:" + name + ":" + puert_serv
                line += " SIP/2.0\r\n\r\n"
                print("Enviando -- ", line)
                my_socket.send(bytes(line, 'utf-8'))

                evento = "Sent to "
                mensaje = line.replace("\r\n", " ")
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

                data = my_socket.recv(1024)
                data = data.decode('utf-8')
                print('Recibido -- ', data)

                evento = "Received from "
                mensaje = data.replace("\r\n", " ")
                log(rutalog, evento, proxy_ip, proxy_port, mensaje)

    except ConnectionRefusedError:
        line = "No listening in " + proxy_ip + ":" + proxy_port
        print(line)
        evento = "Error"
        log(rutalog, evento, proxy_ip, proxy_port, line)

    print("Socket terminado.")
    log(rutalog, evento, proxy_ip, proxy_port, "Finishing.")
