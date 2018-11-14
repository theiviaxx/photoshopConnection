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

import os
import sys
import time
from multiprocessing import Process

import pytest
import six


from pyps import Connection, EventListener, ConnectionError


def callback(message, *args):
    print('callback', message)


def callback2(message, *args):
    print('callbck2', message)


def test_connection():
    c = Connection()
    c.connect('Swordfish')
    assert c.isConnected is True
    c.close()


def test_script():
    c = Connection()
    c.connect('Swordfish')

    res = c.send_sync('$.version;')
    assert res.command == six.b('4.5.8')

    res = c.send_sync('$.os')
    assert res.command == six.b('Windows')

    res = c.send_sync('alert(x);')
    assert res.command == six.b('')

    c.close()


def test_listener():
    c = Connection()
    c.connect('Swordfish')
    c.send_sync('app.foregroundColor.rgb.red=255')

    e = EventListener.connect('Swordfish', interval=0.2)
    e.start()
    e.subscribe('foregroundColorChanged', callback)
    e.subscribe('backgroundColorChanged', callback2)
    time.sleep(1)
    
    c.send_sync('app.foregroundColor.rgb.red=0')
    c.send_sync('app.foregroundColor.rgb.red=10')
    c.send_sync('app.foregroundColor.rgb.red=20')
    c.send_sync('app.foregroundColor.rgb.red=30')
    
    c.send_sync('app.backgroundColor.rgb.red=0')
    c.send_sync('app.backgroundColor.rgb.red=10')
    c.send_sync('app.backgroundColor.rgb.red=20')
    c.send_sync('app.backgroundColor.rgb.red=30')

    i = 0
    while i < 2:
        time.sleep(1)
        i += 1

    e.unsubscribe('foregroundColorChanged', callback)
    e.unsubscribe('backgroundColorChanged', callback2)

    e.stop()
    c.close()

    # def test_no_photoshop(self):
    #     ## -- Test when PS is not running
    #     os.system('TASKKILL /F /IM photoshop.exe')
    #     ## -- wait for ps to stop
    #     time.sleep(1)
    #     c = Connection()
    #     c.connect('Swordfish')
    #     self.assertFalse(c.isConnected)


def f():
    def callback(message, *args):
        print(message.command)
        print(message.content)

    conn = Connection()
    conn.connect(passwd='Swordfish')
    listener = EventListener(conn)
    listener.start()
    listener.subscribe('foregroundColorChanged', callback)
    conn.send_sync('app.foregroundColor.rgb.red=0')
    conn.send_sync('app.foregroundColor.rgb.red=10')
    conn.send_sync('app.foregroundColor.rgb.red=20')
    conn.send_sync('app.foregroundColor.rgb.red=30')
    time.sleep(2)
    print('done')


def test_foo():
    conn = Connection()
    conn.connect(passwd='Swordfish')
    # list(conn.send('alert("Hello");'))

    print(conn.send_sync('$.version;'))

    def callback(message, *args):
        print(message.command)
        print(message.content)


    def callback2(message, *args):
        print(message.command)
        print(message.content)
        print(args)

    listener = EventListener(conn)
    listener.start()
    listener.subscribe('foregroundColorChanged', callback)
    listener.subscribe('documentChanged', callback2, (True, 'xxx'))

    conn.send_sync('app.documents.add(100, 100)')

    print('test_foo')
    time.sleep(3)
    listener.stop()


def test_bad_password():
    conn = Connection()
    conn.connect(passwd='Swordfish1')
    with pytest.raises(ConnectionError):
        conn.send_sync('$.version;')


if __name__ == '__main__':
    p = Process(target=f)
    p.start()
    p.join()
