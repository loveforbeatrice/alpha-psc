#!/bin/bash
sudo apt update
sudo apt install python3 python3-pip
sudo apt install python3-venv  
python3 -m venv ~/alpha-psc-env  

source ~/alpha-psc-env/bin/activate  

chmod +x install.sh
./install.sh

chmod +x ../src/alpha-psc.py  
sudo mv ../src/alpha-psc.py /usr/local/bin/alpha-psc  

chmod +x ~/alpha-psc-env/bin/activate

deactivate 
