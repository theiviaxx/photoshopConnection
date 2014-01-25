## pyps: v0.5
##
## -----------------------------------------------------------------------------
##
## The MIT License (MIT)
##
## Copyright (c) 2013 Brett Dixon
##
## Permission is hereby granted, free of charge, to any person obtaining a copy
## of this software and associated documentation files (the "Software"), to deal
## in the Software without restriction, including without limitation the rights
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
## copies of the Software, and to permit persons to whom the Software is
## furnished to do so, subject to the following conditions:
##
## The above copyright notice and this permission notice shall be included in
## all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
## THE SOFTWARE.

"""A python TCP socket connection to Photoshop CS5.5.  This is a simple
wrapper class to facilitate sending arbitrary JavaScript to Photoshop and
receiving the result of the script.  The Connection objet also has a
thumbnail method to write the a JPEG to a file-like object of the current doc
open in Photoshop.

There is a EventListener class to subscribe to events in Photoshop.
"""


import sys
import socket
import struct
import time
import logging
from threading import Thread
from Queue import Queue

try:
    # PyCrypto is much faster, but requires a built binary
    from Crypto.Cipher import DES3
    PYCRYPTO = True
except ImportError:
    # py_des is pure python, but slower.  Should be ok for sending scripts
    import py_des
    PYCRYPTO = False

from pbkdf2 import PBKDF2

__all__ = ['Connection', 'EventListener']
# _pythonMajorVersion is used to handle Python2 and Python3 differences.
_pythonMajorVersion = sys.version_info[0]

logging.basicConfig()
LOGGER = logging.getLogger('PSLIB')
HOST = socket.gethostbyname(socket.gethostname())
SUBSCRIBE = """
var idNS = stringIDToTypeID( 'networkEventSubscribe' );
var desc1 = new ActionDescriptor();
desc1.putClass( stringIDToTypeID( 'eventIDAttr' ), stringIDToTypeID( '%s' ) );
executeAction( idNS, desc1, DialogModes.NO );
'';
"""


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)

def empty(*args, **kawrgs):
    pass


class Connection(object):
    """Main connection class to Photoshop.  Handles sending/receving and
    encrypting/decrypting the bytes.
    """
    PORT = 49494
    PROTOCOL_VERSION = 1
    PROTOCOL_LENGTH = 4 + 4 + 4
    COMM_LENGTH = 4
    NO_COMM_ERROR = 0

    def __init__(self):
        self._host = None
        self._isConnected = False
        self._socket = socket.socket()
        self._crypt = None
        self._id = 0

    @property
    def isConnected(self):
        return self._isConnected

    def connect(self, host=None, passwd=''):
        host = host or HOST
        try:
            self._socket.connect((host, self.PORT))
            self._socket.settimeout(0.2)
            self._isConnected = True
            LOGGER.debug('Connected')
        except socket.error, e:
            self.socket = None
            self.isConnected = False
            LOGGER.error('Could not connect: %s' % str(e))
        
        self._crypt = EncryptDecrypt(passwd)
    
    def disconnect(self):
        self._socket.close()
        self._socket = None
        self._isConnected = False
        LOGGER.debug('Disconnected')
    
    def recv(self):
        """Receives a message from PS and decrypts it and returns a Message"""
        LOGGER.debug('Receiving')
        try:
            messageLength = struct.unpack('>i', self._socket.recv(4))[0]
            messageLength -= Connection.COMM_LENGTH
            LOGGER.debug('Length: %i' % messageLength)
        except socket.timeout:
            return None
        
        commStatus = struct.unpack('>i', self._socket.recv(4))[0]
        LOGGER.debug('Status: %i' % commStatus)
        bytesReceived = 0
        message = ""
        
        while bytesReceived < messageLength:
            recvLen = 1024 if (messageLength - bytesReceived >= 1024) else messageLength - bytesReceived
            bytesReceived += recvLen
            LOGGER.debug('Received %i' % bytesReceived)
            message += self._socket.recv(recvLen)
        
        if commStatus == 0:
            message = self._crypt.decrypt(message)
        else:
            print message
        
        msg = Message(messageLength, commStatus, message)

        return msg
    
    def send(self, content, recv=False):
        """Sends a JavaScript command to PS

        :param content: Script content
        :param recv: Whether or not to wait for a response.  Good for single commands
        """
        LOGGER.debug('Sending: %s' % content)
        allBytes = struct.pack('>i', Connection.PROTOCOL_VERSION)
        allBytes += struct.pack('>i', self._id)
        allBytes += struct.pack('>i', 2)
        self._id += 1
        for n in content:
            allBytes += struct.pack('>c', n)

        encryptedBytes = self._crypt.encrypt(allBytes)

        messageLength = Connection.COMM_LENGTH + len(encryptedBytes)

        self._socket.send(struct.pack('>i', messageLength))
        self._socket.send(struct.pack('>i', Connection.NO_COMM_ERROR))
        self._socket.send(encryptedBytes)
        LOGGER.debug('Sent')

        if recv:
            ret = self.recv()
            while ret is None:
                ret = self.recv()

            return ret


class EventListener(Thread):
    """Event thread to handle event messages from Photoshop"""
    def __init__(self, connection, interval=None, *args, **kwargs):
        super(EventListener, self).__init__(*args, **kwargs)
        
        self._connection = connection
        self._sub = Queue()
        self._unsub = Queue()
        self._ids = {}
        self._interval = interval

    def subscribe(self, eventName, callback, args=()):
        self._sub.put({'eventName': eventName, 'func': callback, 'args': args})

    def unsubscribe(self, eventName, callback):
        self._unsub.put({'eventName': eventName, 'func': callback})
    
    def run(self):
        while 1:
            ## -- Add any subs
            while self._sub.qsize():
                item = self._sub.get()
                LOGGER.debug('Subscribing %s' % item)
                self._connection.send(SUBSCRIBE % item['eventName'])
                msg = self._connection.recv()
                if msg is not None:
                    self._ids[msg.id] = item

            ## -- Remove subs
            while self._unsub.qsize():
                item = self._unsub.get()
                LOGGER.debug('Unsubscribing %s' % item)
                for id_, sub in self._ids.iteritems():
                    if sub['eventName'] == item['eventName'] and sub['func'] == item['func']:
                        del self._ids[id_]
                        break
            
            ## -- Receive bytes from PS
            message = self._connection.recv()
            if message is None:
                continue
            
            obj = self._ids.get(message.id)
            if obj:
                obj['func'](message, *obj['args'])

            if self._interval:
                time.sleep(self._interval)


class EncryptDecrypt(object):
    """Handles the encrypting and dectrypting of bytes"""
    def __init__(self, passPhrase):
        SALT = 'Adobe Photoshop'
        ITERACTIONCOUNT = 1000
        KEY_LENGTH = 24

        key = PBKDF2(bytes(passPhrase), bytes(SALT), iterations=ITERACTIONCOUNT).read(KEY_LENGTH)
        iv = '\0\0\0\0\0\0\0\0'
        self.block_size = 8

        if PYCRYPTO:
            self.enc = DES3.new(key, DES3.MODE_CBC, iv)
            self.dec = DES3.new(key, DES3.MODE_CBC, iv)
        else:
            self.enc = py_des.triple_des(key, py_des.CBC, iv, padmode=py_des.PAD_PKCS5)
            self.dec = py_des.triple_des(key, py_des.CBC, iv, padmode=py_des.PAD_PKCS5)

    def encrypt(self, b):
        data = self._padData(b) if PYCRYPTO else b
        return self.enc.encrypt(data)

    def decrypt(self, byteString):
        data = self.dec.decrypt(byteString)
        return self._unpadData(data) if PYCRYPTO else data

    # Stolen from py_des for PKCS5 padding when using PyCrypto
    def _padData(self, data):
        pad_len = 8 - (len(data) % self.block_size)
        if _pythonMajorVersion < 3:
            data += pad_len * chr(pad_len)
        else:
            data += bytes([pad_len] * pad_len)

        return data

    def _unpadData(self, data):
        # Unpad data depending on the mode.
        if not data:
            return data

        if _pythonMajorVersion < 3:
            pad_len = ord(data[-1])
        else:
            pad_len = data[-1]
        data = data[:-pad_len]

        return data

    def _guardAgainstUnicode(self, data):
        # Only accept byte strings or ascii unicode values, otherwise
        # there is no way to correctly decode the data into bytes.
        if _pythonMajorVersion < 3:
            if isinstance(data, unicode):
                raise ValueError("py_des can only work with bytes, not Unicode strings.")
        else:
            if isinstance(data, str):
                # Only accept ascii unicode values.
                try:
                    return data.encode('ascii')
                except UnicodeEncodeError:
                    pass
                raise ValueError("py_des can only work with encoded strings, not Unicode.")
        return data


class Message(object):
    """Simple object to present Photoshop messages nicely"""
    ContentType = enum('ERROR', 'JAVASCRIPT', 'IMAGE', 'ICC', 'DATA')
    Status = enum('OK', 'ERROR')
    def __init__(self, length, status, message):
        self.length = length
        self.status = status
        self._message = message
        messageHead = 4 * 3 # 4 bytes for each of the following
        self.version = struct.unpack('>i', message[:4])[0]
        self.id = struct.unpack('>i', message[4:8])[0]
        self.type = struct.unpack('>i', message[8:12])[0]

        # The rest is the message
        splits = message[messageHead:].split('\r', 2)
        if len(splits) < 2:
            self.command = splits[0]
            self.content = ''
        else:
            self.command = splits[0]
            self.content = splits[1]

    def __repr__(self):
        return '<%s : %s>' % (self.command, self.content)


if __name__ == '__main__':
    conn = Connection()
    conn.connect(passwd='Swordfish')
    conn.send('alert("Hello");', True)

    print conn.send('$.version;', True)

    def callback(message, *args):
        print message.command
        print message.content

    def callback2(message, *args):
        print message.command
        print message.content
        print args
    
    # conn1 = Connection()
    # conn1.connect(passwd='Swordfish')
    listener = EventListener(conn)
    listener.start()
    listener.subscribe('foregroundColorChanged', callback)
    listener.subscribe('toolChanged', callback2, (True, 'xxx'))
    listener.subscribe('currentDocumentChanged', callback)
    
    ## -- We need to keep the EventListener alive
    while True:
        time.sleep(1.0)
