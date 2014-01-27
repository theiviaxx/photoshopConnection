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
import time
import unittest

from pyps import Connection, EventListener


def callback(message, *args):
    pass


class PSTestSuite(unittest.TestCase):
    def test_connection(self):
        
        c = Connection()
        c.connect('Swordfish')
        self.assertTrue(c.isConnected)
        c.close()

        c = Connection()
        c.connect('badpass')
        res = c.send('$.version', True)
        self.assertEqual(res.command, 'ERROR')

        c.close()

    def test_script(self):
        c = Connection()
        c.connect('Swordfish')

        res = c.send('$.version;', True)
        self.assertEqual(res.command, '4.1.28')
        self.assertEqual(repr(res), '<4.1.28:>')

        c.send('$.sleep(2000);', True)

        res = c.send('alert(x);', True)
        self.assertEqual(res.command, 'Error 2: x is undefined.')

        c.close()

    def test_listener(self):
        c = Connection()
        c.connect('Swordfish')
        print c.send('app.foregroundColor.rgb.red=255', True)

        e = EventListener('Swordfish', interval=0.2)
        e.start()
        e.subscribe('foregroundColorChanged', callback)
        time.sleep(1)
        c.send('app.foregroundColor.rgb.red=0', True)
        c.send('app.foregroundColor.rgb.red=10', True)
        c.send('app.foregroundColor.rgb.red=20', True)
        c.send('app.foregroundColor.rgb.red=30', True)
        e.unsubscribe('foregroundColorChanged', callback)
        i = 0
        while i < 2:
            time.sleep(1)
            i += 1

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