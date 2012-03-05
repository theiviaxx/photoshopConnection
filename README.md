Photoshop Connection
--------------------
A python TCP socket connection to Photoshop CS5.5.  This is a simple
wrapper class to facilitate sending arbitrary JavaScript to Photoshop and
receiving the result of the script.  The Connection objet also has a
thumbnail method to write the a JPEG to a file-like object of the current doc
open in Photoshop.

There is a EventListener class to subscribe to events in Photoshop.

Example
-------

    from photoshopConnection.connection import Connection, EventListener
    
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