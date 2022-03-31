import socket
from time import sleep

payload = "30819102"\
          "010104067075626c6963a78183020469"\
          "1421910201000201003075301006082b"\
          "0601020101030043040219a7fd301606"\
          "0a2b06010603010104010006082b0601"\
          "02010f0702301606102b060102010f03"\
          "010e8140812803814a04020000301506"\
          "102b060102010f030102814081280381"\
          "4a020101301a060a2b06010603010104"\
          "0300060c2b06010401944c010101020e";


msg_counter = 1
serverAddressPort   = ("127.0.0.1", 162)
bufferSize          = 1000

 

# Create a UDP socket at client side

UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

for i in range(msg_counter):
	bytesToSend = bytes.fromhex(payload)
	UDPClientSocket.sendto(bytesToSend, serverAddressPort)
	sleep(0.02)