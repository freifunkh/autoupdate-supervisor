#!/usr/bin/python
import time
import socket
import threading
import tempfile
import socketserver
from subprocess import run, PIPE

ecdsatool_executable = 'ecdsasign'

def signer(key_file):
    def sign(challenge):
        """ This function calls the ecdsatool_executable to sign a certain challenge. """
        tmp_file = tempfile.mktemp()
        with open(tmp_file, 'w') as f:
            f.write(challenge)

        with open(key_file) as secret:
            response = run([ecdsatool_executable, tmp_file], stdin=secret, stdout=PIPE)

        return response.stdout
    return sign

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ChallengeHandler(socketserver.BaseRequestHandler):
    """ A TCP-Connection handler, that receives challenges, signes them,
    and displays info notices from the clients. """

    def info(self):
        """ This function will be called, if a client send's a info notice. """
        print(self.data)

    def challenge(self):
        """ Hold the connection until the challenge appears in the list
        of allowed challenges. When the challenge appears, the challenge
        will be signed with the secret. The signature will be sent back to 
        the client. """

        node = self.client_address[0]

        # remove the instruction at the beginning of the response,
        # since it is not part of the signable content
        self.data = self.data.replace('CHALLENGE:', '')
        
        print('CONNECT:', node, self.data)
        
        while True:
            with open(ChallengeHandler.allowed_file) as f:
                if self.data in f.read():
                    break
            time.sleep(5)
        
        self.request.send(ChallengeHandler.sign(self.data))
    
    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip().decode('utf-8')

        if self.data.startswith('CHALLENGE'):
            self.challenge()
        else:
            self.info()
        
        
if __name__ == "__main__":
    try:
        # the routers use ipv6, port 12345 to connect
        conn = "::", 12345
        socketserver.TCPServer.address_family = socket.AF_INET6

        c = ChallengeHandler

        c.allowed_file = './allowed'
        c.sign = signer('./key')
       
        # a threaded tcp server is used
        server = ThreadedTCPServer(conn, c)
    
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C

        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()                                                                        
