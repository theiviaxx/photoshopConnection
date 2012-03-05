#############################################################################
# 				Documentation				    #
#############################################################################
"""A python TCP socket connection to Photoshop CS5.5.  This is a simple

wrapper class to facilitate sending arbitrary JavaScript to Photoshop and
receiving the result of the script.  The Connection objet also has a
thumbnail method to write the a JPEG to a file-like object of the current doc
open in Photoshop.

There is a EventListener class to subscribe to events in Photoshop.

Example
-------

from photoshopConnectio import Connection, Listener

conn = Connection()
conn.connect('Swordfish')
conn.sendJavascript('alert("Hello World");')

msg = conn.sendJavascript('$.version;')
print msg.content

fh = open('/tmp/thumbnail.jpg', 'wb')
conn.thumbnail(fh, 300, 200)
fh.close()

def callback(message):
    print message.content

listener = EventListener()
listener.connect('Swordfish')
listener.subscribe('foregroundColorChanged', callback)

"""



import sys
import socket
import struct

try:
    # PyCrypto is much faster, but requires a built binary
    from Crypto.Cipher import DES3
    PYCRYPTO = True
except ImportError:
    # pyDes is pure python, but slower.  Should be ok for sending scripts
    import pyDes
    PYCRYPTO = False

from pbkdf2 import PBKDF2

__all__ = ['Connection', 'Listener']
# _pythonMajorVersion is used to handle Python2 and Python3 differences.
_pythonMajorVersion = sys.version_info[0]


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)

def empty(*args, **kawrgs):
    pass


class Connection(object):
    PORT = 49494
    PROTOCOL_VERSION = 1
    PROTOCOL_LENGTH = 4 + 4 + 4
    COMM_LENGTH = 4
    NO_COMM_ERROR = 0
    
    def __init__(self, host=None):
        self.host = host or socket.gethostbyname(socket.gethostname())
        self.isConnected = False
        self.socket = None
        self.passwd = ""
    
    def connect(self, passwd):
        self.passwd = passwd
        try:
            self.socket = socket.socket()
            self.socket.connect((self.host, Connection.PORT))
            self.isConnected = True
        except socket.error:
            self.socket = None
            self.isConnected = False
    
    def sendJavascript(self, script, receive=True):
        if self.isConnected:
            ed = EncryptDecrypt(self.passwd)
            allBytes = struct.pack('>i', Connection.PROTOCOL_VERSION)
            for n in script:
                allBytes += struct.pack('>c', n)
            
            encryptedBytes = ed.encrypt(allBytes)
            
            messageLength = Connection.COMM_LENGTH + len(encryptedBytes)
        
            self.socket.send(struct.pack('>i', messageLength))
            self.socket.send(struct.pack('>i', Connection.NO_COMM_ERROR))
            self.socket.send(encryptedBytes)
            if receive:
                messageLength = struct.unpack('>i', self.socket.recv(4))[0]
                bytesReceived = 0
                message = ""
                while bytesReceived != messageLength:
                    recvLen = 1024 if (messageLength - bytesReceived >= 1024) else messageLength - bytesReceived
                    bytesReceived += recvLen
                    message += self.socket.recv(recvLen)
                msg = Messge(messageLength, message)
                
                return msg
            else:
                return True
        else:
            return False
    
    def thumbnail(self, fileObj, width=200, height=None):
	height = height or width
	
	script = 'var idNS = stringIDToTypeID( "sendDocumentThumbnailToNetworkClient" );'
	script += 'var desc1 = new ActionDescriptor();'
	script += 'desc1.putInteger( stringIDToTypeID( "width" ), %i );' % width
	script += 'desc1.putInteger( stringIDToTypeID( "height" ), %i );' % height
	script += 'desc1.putInteger( stringIDToTypeID( "format" ), 1 );'
	script += 'executeAction( idNS, desc1, DialogModes.NO );'
	
	msg = self.sendJavascript(script)
	if msg.status == Messge.Status.OK:
	    # The first 4 bytes are the type, which for this module, we only use JPG
	    fileObj.write(msg.content[4:])
	
	return msg


class EventListener(object):
    def __init__(self):
	self.IDs = {}
    
    def connect(self, passwd):
	self.socket = Connection()
	self.socket.connect(passwd)
    
    def subscribe(self, eventName, callback=empty):
	script = "var idNS = stringIDToTypeID( 'networkEventSubscribe' );"; 
	script += "var desc1 = new ActionDescriptor();";
	script += "desc1.putClass( stringIDToTypeID( 'eventIDAttr' ), stringIDToTypeID( '" + eventName + "' ) );";
	script += "executeAction( idNS, desc1, DialogModes.NO );";
	script += "''";
	msg = self.socket.sendJavascript(script);
	
	self.IDs[msg.id] = callback


class EncryptDecrypt(object):
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
	    self.enc = pyDes.triple_des(key, pyDes.CBC, iv, padmode=pyDes.PAD_PKCS5)
	    self.dec = pyDes.triple_des(key, pyDes.CBC, iv, padmode=pyDes.PAD_PKCS5)
    
    def encrypt(self, b):
	data = self._padData(b) if PYCRYPTO else b
        return self.enc.encrypt(data)
    
    def decrypt(self, byteString):
	data = self.dec.decrypt(byteString)
        return self._unpadData(data) if PYCRYPTO else data
    
    # Stolen from pyDes for PKCS5 padding when using PyCrypto
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
		raise ValueError("pyDes can only work with bytes, not Unicode strings.")
	else:
	    if isinstance(data, str):
		# Only accept ascii unicode values.
		try:
		    return data.encode('ascii')
		except UnicodeEncodeError:
		    pass
		raise ValueError("pyDes can only work with encoded strings, not Unicode.")
	return data


class Messge(object):
    ContentType = enum('ERROR', 'JAVASCRIPT', 'IMAGE', 'ICC', 'DATA')
    Status = enum('OK', 'ERROR')
    def __init__(self, length, message):
        self.length = length
        messageHead = 4 * 4 # 4 bytes for each of the following
        self.status = struct.unpack('>i', message[0:4])[0]
        self.version = struct.unpack('>i', message[4:8])[0]
        self.id = struct.unpack('>i', message[8:12])[0]
        self.type = struct.unpack('>i', message[12:16])[0]
        
        # The rest is the message
        self.content = message[messageHead:]


if __name__ == '__main__':
    conn = Connection()
    conn.connect('Swordfish')
    conn.sendJavascript('alert("Hello World");')
    
    msg = conn.sendJavascript('$.version;')
    print msg.content
    
    def callback(message):
	print message.content
    
    listener = EventListener()
    listener.connect('Swordfish')
    listener.subscribe('foregroundColorChanged', callback)