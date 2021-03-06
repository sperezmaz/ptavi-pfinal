#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Cliente UA que funciona como servidor. Envia el audio via RTP al otro UA."""

import socketserver
import sys
import threading
from os import system
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import XMLClientHandler
from uaclient import vlc
from uaclient import viartp
from uaclient import log
import time


class SIPHandlerServer(socketserver.DatagramRequestHandler):
    """Server class."""

    escucha = False
    puerto_rtp_dest = []
    ip_rtp_dest = []

    def handle(self):
        """handle method of the server class."""
        # Escribe dirección y puerto del cliente (de tupla client_address)
        line = self.rfile.read()
        print('Recibido -- ', line.decode('utf-8'))

        evento = "Received from "
        mensaje = line.decode('utf-8').replace("\r\n", " ")
        log(rutalog, evento, proxy_ip, proxy_port, mensaje)

        message = line.decode('utf-8').split()
        metodo = message[0]
        ip_client = self.client_address[0]

        if metodo == "INVITE" and not SIPHandlerServer.escucha:
            line2 = "Content-Type: application/sdp\r\n\r\nv=0\r\no=" + usuario
            line2 += " " + ip_serv + "\r\ns=lasesion\r\nt=0\r\nm=audio "
            line2 += puerto_rtp + " RTP\r\n"
            line = "SIP/2.0 100 Trying\r\n\r\n" + "SIP/2.0 180 Ringing\r\n\r\n"
            line += "SIP/2.0 200 OK\r\n" + line2
            self.wfile.write(bytes(line, 'utf-8'))
            print("Enviando -- ", line)
            mensaje = line.replace("\r\n", " ")

            ip_rtp = message[7]
            port_rtp = message[11]
            self.ip_rtp_dest.append(ip_rtp)
            self.puerto_rtp_dest.append(port_rtp)
            SIPHandlerServer.escucha = True

        elif metodo == "INVITE" and SIPHandlerServer.escucha:
            line = "SIP/2.0 480 Temporarily Unavailable\r\n\r\n"
            self.wfile.write(bytes(line, 'utf-8'))
            print("Enviando -- ", line)
            mensaje = line.replace("\r\n", " ")

        elif metodo == "ACK":
            hilo1 = threading.Thread(target=viartp, args=(self.ip_rtp_dest[0],
                                     self.puerto_rtp_dest[0], fichero_audio,))
            hilo2 = threading.Thread(target=vlc, args=(ip_serv,
                                     puerto_rtp,))
            hilo2.start()
            hilo1.start()

            evento = "Sent to "
            mensaje = "RTP"

        elif metodo == "BYE":
            system("killall vlc 2> /dev/null")
            system("killall mp32rtp 2> /dev/null")
            line = "SIP/2.0 200 OK\r\n\r\n"
            self.wfile.write(bytes(line, 'utf-8'))
            print("Enviando -- ", line)
            mensaje = line.replace("\r\n", " ")

            SIPHandlerServer.escucha = False

        elif metodo not in ["INVITE", "ACK", "BYE"]:
            line = "SIP/2.0 405 Method Not Allowed\r\n\r\n"
            self.wfile.write(bytes(line, 'utf-8'))
            print("Enviando -- ", line)
            mensaje = line.replace("\r\n", " ")

        else:
            line = "SIP/2.0 400 Bad Request\r\n\r\n"
            self.wfile.write(bytes(line, 'utf-8'))
            print("Enviando -- ", line)
            mensaje = line.replace("\r\n", " ")

        evento = "Sent to "
        log(rutalog, evento, proxy_ip, proxy_port, mensaje)

if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit("Usage: python uaserver.py config")
    parser = make_parser()
    cHandler = XMLClientHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    datos = cHandler.get_tags()

    proxy_ip = datos["regproxy"]["ip"]
    proxy_port = datos['regproxy']['puerto']
    usuario = datos['account']['username']
    puerto_rtp = datos['rtpaudio']['puerto']
    ip_serv = datos['uaserver']['ip']
    port_serv = datos['uaserver']['puerto']
    fichero_audio = datos['audio']['path']
    rutalog = datos['log']['path']

    # Creamos servidor y escuchamos
    serv = socketserver.UDPServer((ip_serv, int(port_serv)), SIPHandlerServer)
    print("Listening...")

    try:
        serv.serve_forever()  # espera en un bucle
    except KeyboardInterrupt:  # ^C
        print("Finalizado servidor")
