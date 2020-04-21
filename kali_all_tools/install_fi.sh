#!/bin/bash
if [ -z $1 ] 
then
        echo "enter the location to install the files";
        exit;
fi 
mkdir $1/tools
cp * $1/tools
cd $1/tools
for i in $(cat git)
do
        git clone $i
done
echo "****************************************";
echo "finish to download the tools from Github"; 
echo "****************************************";
for i in $(cat dpkgkali)
do 
        apt -y install $i
done
echo "***********************";
echo "finish to install tools"; 
echo "***********************";
for i in $(cat wget)
do
        wget $i
done
echo "***********************";
echo "finish to download tools"; 
echo "***********************";
apt install python3-pip
for i in $(cat pip3)
do
        pip3 install $i
done
echo "************************";
echo "finish to pip3 tools"; 
echo "************************";
