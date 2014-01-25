Photoshop Connection
--------------------

Photoshop Connection is released under the MIT license. It is simple and easy to understand and places almost no restrictions on what you can do with Photoshop Connection.
[More Information](http://en.wikipedia.org/wiki/MIT_License)

A python TCP socket connection to Photoshop CS5.5.  This is a simple
wrapper class to facilitate sending arbitrary JavaScript to Photoshop and
receiving the result of the script.  The Connection objet also has a
thumbnail method to write the a JPEG to a file-like object of the current doc
open in Photoshop.

There is a EventListener class to subscribe to events in Photoshop.

Example
-------

    from pyps import Connection, EventListener
    
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

    listener = EventListener(conn)
    listener.start()
    listener.subscribe('foregroundColorChanged', callback)
    listener.subscribe('toolChanged', callback2, (True, 'xxx'))
    listener.subscribe('currentDocumentChanged', callback)
    
    ## -- We need to keep the EventListener alive
    while True:
        time.sleep(1.0)