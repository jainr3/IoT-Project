import socket
import time
import threading
from Crypto.Cipher import AES
import requests
import numpy as np
import random
import base64

port = 9999

# Need to configure these... (reserve IP on network)
ESP_device_1_IP = "192.168.86.219"
ESP_device_2_IP = "192.168.86.220"
RPi_device_1_IP = "192.168.86.217" # Control node
RPi_device_2_IP = "192.168.86.218"

RSSI_time_threshold = 20 # amount of seconds before we reset the rssi to low value
HTTP_request_threshold = 10 # amount of time between HTTP requests for device updates
RSSI_THRESHOLD = -60 # Minimum RSSI value needed to be "in a room" after determining closest beacon

# Maintain a dictionary of the last known RSSIs of the devices
devices_and_rssis = {} # Entry looks like: key: [MAC] value: ([4 RSSIs], [4 last updated times])

def parse_data(sender, data):
    # Sender is the IP of the node that sent the update
    # Given a string of MAC=rssi;MAC=rssi; etc
    # Parse the string and update the dictionary
    parsed = data.split(";")[:-1]
    for entry in parsed:
        MAC, rssi = entry.split("=")
        # Have to make uppercase the MACs for the ESP devices
        MAC = MAC.upper()
        if MAC not in devices_and_rssis:
            current_time = time.time()
            # Just setting up the new dictionary entry before we put stuff into it
            devices_and_rssis[MAC] = ([-140, -140, -140, -140], [current_time, current_time, current_time, current_time])
        if (sender == ESP_device_1_IP):
            devices_and_rssis[MAC][0][0] = int(rssi)
            devices_and_rssis[MAC][1][0] = time.time()
        elif (sender == ESP_device_2_IP):
            devices_and_rssis[MAC][0][1] = int(rssi)
            devices_and_rssis[MAC][1][1] = time.time()
        elif (sender == RPi_device_1_IP):
            devices_and_rssis[MAC][0][2] = int(rssi)
            devices_and_rssis[MAC][1][2] = time.time()
        elif (sender == RPi_device_2_IP):
            devices_and_rssis[MAC][0][3] = int(rssi)
            devices_and_rssis[MAC][1][3] = time.time()
        else:
            print("Unknown sender", sender)
    print(devices_and_rssis)

def refresh_dict():
    # Run this periodically to remove stale entries from dictionary
    while(True):
        print("refreshing")
        current_time = time.time()
        devices_to_remove = []
        for MAC in devices_and_rssis.keys():
            # Check if any RSSI values that do exist are stale
            time_index = 0 # Keeps track of which time we are comparing
            for old_time in devices_and_rssis[MAC][1]:
                if (devices_and_rssis[MAC][0][time_index] == -140):
                    print("rssi still not updated, val at", devices_and_rssis[MAC][0][time_index])
                elif (current_time - old_time > RSSI_time_threshold):
                    print("stale value for rssi found")
                    print(devices_and_rssis)
                    # Reset the RSSI corresponding to the time/rssi index
                    devices_and_rssis[MAC][0][time_index] = -140
                    devices_and_rssis[MAC][1][time_index] = current_time
                time_index += 1
            # Remove any entries that are all -140 from dictionary, since the device hasn't been heard from in a 'long time'
            # Do this after the stale RSSI check since RSSIs were just updated
            if (devices_and_rssis[MAC][0] == [-140, -140, -140, -140]):
                devices_to_remove.append(MAC)
                print("all -140, remove device")
        msg = ""
        for device in devices_to_remove: #Remove old devices
            devices_and_rssis.pop(MAC)
            msg += device
            msg += "=H;"
        if (len(devices_to_remove) != 0):
            print("redirecting back to home page")
            # Send devices that are no longer in the area back to the home page H
            e_msg = base64.b64encode(encrypt_token(msg))
            response=requests.post('https://pacific-springs-58488.herokuapp.com/rasppi',data={"data":e_msg})
        time.sleep(RSSI_time_threshold)

def localize():
    print("localizing")
    msg = ""
    locations = ["A", "B", "C", "D", "H"] # Physical locations of devices
    for device in devices_and_rssis.keys():
        msg += device
        device_rssis = np.array(devices_and_rssis[device][0])
        device_location = np.where(device_rssis == device_rssis.max()) # Determine which entry has lowest RSSI (max since -), returns array
        # If the threshold is not reached, put the person in Room "H"
        if (device_rssis.max() < RSSI_THRESHOLD):
            device_location = 4
            print(device, "not close to any room, missed threshold")
            continue
        # If there are ties, handle by randomly selecting from the list (if there is only one, it will select that one entry)
        device_location = random.choice(device_location)[0] # turns the array into a integer
        msg += "="
        msg += locations[device_location]
        msg += ";"
    return msg

def send_dict():
    while(True):
        time.sleep(HTTP_request_threshold)
        # Localize the devices in dict: devices_and_rssis
        localized_msg = localize()
        # Encrypt the message and then make POST request
        if (localized_msg == ""):
            continue
        e_msg = base64.b64encode(encrypt_token(localized_msg))
        #print('Python encrypt: ' + str(e_msg))
        
        response=requests.post('https://pacific-springs-58488.herokuapp.com/rasppi',data={"data":e_msg})
        #print("Statuscode:",response.status_code)
        #print(response.json())

def _pad(s): return (s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)).encode("utf8")
def _cipher():
    key = '7fkgy8fhsk7wmwfs0fhekcm38dhtusn3'
    iv = '0000000000000000'
    return AES.new(key=key.encode("utf8"), mode=AES.MODE_CBC, IV=iv.encode("utf8"))

def encrypt_token(data):
    return _cipher().encrypt(_pad(data))

def decrypt_token(data):
    return _cipher().decrypt(data)

def decrypt_AES(encrypted_bytes):
    # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
    iv = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    key = "7fkgy8fhsk7wmwfs0fhekcm38dhtusn3" # Assume preshared
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(encrypted_bytes)

# Code to run the refresh dictionary on a separate thread
t1 = threading.Thread(target=refresh_dict, args=[])
t1.start()

t2 = threading.Thread(target=send_dict, args=[])
t2.start()

try:
    s = socket.socket()

    # bind to input port
    s.bind(('', port))
    print("Server is listening to port %d" %(port))

    s.listen(6) # Make it large enough so we can have at least 4 connections

    addr=''
    while True:
        print("="*30)
        print("waiting for connection")

        c, addr = s.accept()
        print ('Got connection from', addr)

        ## message transmission
        # receive message from the client(s)
        rmsg_bytes = c.recv(1024)
        # Before turning into a string, first decrypt the bytes & strip whitespace
        # print(''.join(format(x, '02x') for x in rmsg_bytes))
        rmsg_bytes = decrypt_AES(rmsg_bytes)

        rmsg = rmsg_bytes.decode().strip()
        print("client: ", rmsg)
        parse_data(addr[0], rmsg)

        # Close the connection with the client 
        c.close() 
except ConnectionRefusedError:
    print("Connection refused.")
finally:
    print("socket is free")
    s.close()
