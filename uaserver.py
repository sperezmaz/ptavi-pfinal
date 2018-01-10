#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""Cliente UA que funciona como servidor. Envia el audio via RTP al otro UA."""

import socketserver
import sys
import threading
from os import system
from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import XMLHandler
from uaclient import vlc
from uaclient import viartp
import time


class SIPHandlerServer(socketserver.DatagramRequestHandler):
    """Echo server class."""
    escucha = False
    puerto_rtp_dest = []
    ip_rtp_dest = []
    def handle(self):
        """handle method of the server class."""
        # Escribe dirección y puerto del cliente (de tupla client_address)
        line = self.rfile.read()
        print('Recibido -- ', line.decode('utf-8'))
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
            ip_rtp = message[7]
            port_rtp = message[11]
            self.ip_rtp_dest.append(ip_rtp)
            self.puerto_rtp_dest.append(port_rtp)
            SIPHandlerServer.escucha = True
        elif metodo == "INVITE" and SIPHandlerServer.escucha:    
            self.wfile.write(b"SIP/2.0 480 Temporarily Unavailable\r\n\r\n")
            print("Enviando -- SIP/2.0 480 Temporarily Unavailable")
        elif metodo == "ACK":
            hilo1 = threading.Thread(target=viartp, args=(self.ip_rtp_dest[0], 
                                     self.puerto_rtp_dest[0], fichero_audio,))
            hilo2 = threading.Thread(target=vlc, args=(ip_serv, 
                                     puerto_rtp,))
            hilo1.start()
            hilo2.start()
        elif metodo == "BYE":
            system("killall vlc 2> /dev/null")
            system("killall mp32rtp 2> /dev/null")
            self.wfile.write(b"SIP/2.0 200 OK\r\n\r\n")
            SIPHandlerServer.escucha = False
        elif metodo not in ["INVITE", "ACK", "BYE"]:
            self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n\r\n")
        else:
            self.wfile.write(b"SIP/2.0 400 Bad Request\r\n\r\n")


if __name__ == "__main__":
    try:
        CONFIG = sys.argv[1]
    except:
        sys.exit("Usage: python uaserver.py config")
    parser = make_parser()
    cHandler = XMLHandler()
    parser.setContentHandler(cHandler)
    parser.parse(open(CONFIG))
    # print(cHandler.get_tags())
    datos = cHandler.get_tags()
    
    usuario = datos['account']['username']
    puerto_rtp = datos['rtpaudio']['puerto']
    ip_serv = datos['uaserver']['ip']
    port_serv = datos['uaserver']['puerto']
    fichero_audio = datos['audio']['path']
    # Creamos servidor y escuchamos
    serv = socketserver.UDPServer((ip_serv, int(port_serv)), SIPHandlerServer)
    print("Listening...")
    try:
        serv.serve_forever()  # espera en un bucle
    except KeyboardInterrupt:  # ^C
        print("Finalizado servidor")
