#!/bin/bash
wget https://raw.githubusercontent.com/ahronmoshe/hack-assistance/master/tools  /root/tools.txt
mkdir /root/tools
cd /root/tools
for i in $(cat /root/tools.txt)
do
	git clone $i
done
wget https://raw.githubusercontent.com/ahronmoshe/hack-assistance/master/dpkgkali -o /root/dpkgkali.txt
for i in $(cat /root/dpkgkali.txt)
do 
	apt -y install $i
done
