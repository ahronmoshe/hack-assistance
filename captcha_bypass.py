import os
import cv2
try:
    from PIL import Image
except ImportError:
    import Image
import pytesseract
from urllib.error import *
from urllib.request import *

from urllib.parse import *
import subprocess
import urllib, requests, re, json

urlglobal="http://192.168.35.146/captcha/example7/"
def getpage():
    try:
        print("[+] Download page ");
        site = urllib.request.urlopen(urlglobal)
        global cookie
        cookie = site.getheader('Set-Cookie')
        print("-----Cookie: " + cookie);
        site_html = site.read().decode("utf-8")
        # print(site_html)
        global token
        # Obtener el token (10 numeros + . + 7 numeros
        token = re.findall('[(\d+.\d+)]{18}', site_html)
        print("-----Token: " + token[0])
    except URLError as e:
        print("*****Error: can't download the page*****");


def getcaptcha():
    try:
        print("[+] Download Captcha");
        captchaurl = urlglobal + "captcha.png?t=" + token[0]
        urlretrieve(captchaurl, 'captcha.png')
    except URLError as e:
        print("*****Error: can't download the page*****");


def resizer():
    print("[+] Changing the size...");
    im1 = Image.open("captcha.png")
    width, height = im1.size
    im2 = im1.resize((int(width * 5), int(height * 5)), Image.BICUBIC)
    im2.save("captcha1.png")


def tesseract():
    try:
        print("[+] Running Tesseract...");
        # Run Tesseract, -psm 8, tells Tesseract we are looking for a single word
        #subprocess.call(['tesseract', 'captcha1.png', 'output', '-psm', '8'])
        pytesseract.pytesseract.tesseract_cmd = "C:\\Program Files\\Tesseract-OCR\\tesseract.exe"
        global cvalue
        image = cv2.imread('./captcha1.png', 0)
        imgBlur = cv2.GaussianBlur(image, (9, 9), 0)
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
        imgTH = cv2.morphologyEx(imgBlur, cv2.MORPH_TOPHAT, kernel)
        imgBin = cv2.threshold(imgTH, 0, 250, cv2.THRESH_OTSU)
        imgdil = cv2.dilate(imgBin, kernel)
        imgBin_Inv = cv2.threshold(imgdil, 0, 250, cv2.THRESH_BINARY_INV)
        cv2.imwrite('./captcha2.png', imgBin_Inv)
        cv2.waitKey(0)
        #os.system('convert captcha1.png -white-threshold 1% captcha2.png')
        cvalue = pytesseract.image_to_string(Image.open("captcha2.png"))
        #f = open("output.txt", "r")
        #print(f)
        # Borra los espacios en blanco y las nuevas lineas de la salida Tesseract
        #cvaluelines = f.read().replace(" ", "").split('\n')
        #cvalue = cvaluelines[0]
        print("-----Captcha: " + cvalue);
    except Exception as e:
        print("Error: " + str(e))


def send():
    try:
        print("[+] Send the request...");
        urlconcaptcha = urlglobal+"submit?captcha=" + str(cvalue) + "&Submit+Query"
        print("-----URL: " + urlconcaptcha);
        request = urllib.request.Request(urlconcaptcha, headers={'Cookie': cookie})
        f = urlopen(request)
        response = f.read().decode('utf-8')
        # print(response)
        exito = re.search('Success', response)
        if exito:
            print("-----Got it !")

        else:
            print("-----Fail!")
    except Exception as e:
        print("Error: " + str(e))

print("[+] Starting!")
getpage()
getcaptcha()
resizer()
tesseract()
send()
print("[+] Finish!")
