## mac changer + tor

mac_changer.py -i eth0 -m random

mac_changer.py -i en0 -m 00:11:22:33:44:55

mac_changer.py -i eth0 -m random --tor

mac_changer.py -i eth0 -m random --tor --tor-port 9051 --tor-password secret

mac_changer.py -i eth0 --restore


# #  Install and Requirements:

python3 -m venv venv

source venv/bin/activate

pip install stem (only if --tor is used)
