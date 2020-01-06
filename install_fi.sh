#!/bin/bash
wget https://raw.githubusercontent.com/ahronmoshe/hack-assistance/master/tools -O /root/tools.txt
mkdir /root/tools
cd /root/tools
for i in $(cat /root/tools.txt)
do
	git clone $i
done
echo "****************************************";
echo "finish to download the tools from Github"; 
echo "****************************************";
wget https://raw.githubusercontent.com/ahronmoshe/hack-assistance/master/dpkgkali -O /root/dpkgkali.txt
for i in $(cat /root/dpkgkali.txt)
do 
	apt -y install $i
done
echo "***********************";
echo "finish to install tools"; 
echo "***********************";
wget https://raw.githubusercontent.com/ahronmoshe/hack-assistance/master/wget -O /root/wget.txt
for i in $(cat /root/wget.txt)
do
	wget $i
done
echo "***********************";
echo "finish to download tools"; 
echo "***********************";
wget https://raw.githubusercontent.com/ahronmoshe/hack-assistance/master/pip3 -O /root/pip3.txt
for i in $(cat /root/wget.txt)
do
	pip3 install $i
done
echo "************************";
echo "finish to pip3 tools"; 
echo "************************";
