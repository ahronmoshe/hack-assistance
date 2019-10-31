#!/usr/bin/python3
import sys;
import re
import webbrowser

if (len(sys.argv) <= 1 ):
        print("what is the file??")
        print("This script is open multiple URL from file")
        sys.exit()
print("Open URLS!")
with open(sys.argv[1]) as f:
        file =f.read()
        urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F>
for i in urls:
        print(i)
        webbrowser.open_new_tab(i)

print("Did you find what you looking for")

