# IoT Final Project
ECSE 4660 Internetworking of Things Spring 2021

Author: Rahul Jain

## Summary

A program for detecting & localizing Bluetooth Classic devices using Raspberry Pi and ESP32 as IoT nodes. 

## Hardware Prerequisites
* Two [Raspberry Pi 3B+](https://www.amazon.com/ELEMENT-Element14-Raspberry-Pi-Motherboard/dp/B07P4LSDYV/) devices (RPi)
* Two [ESP32](https://www.amazon.com/MELIFE-Development-Dual-Mode-Microcontroller-Integrated/dp/B07Q576VWZ/) devices; [Official Site](http://esp32.net/)
* A few cell phones with Bluetooth Classic

## Running Bluetooth Scanning / Localization Scripts on RPi
* Connect RPi to WiFi network and enable Bluetooth capabilities
* Reserve IPs for the RPis as needed, modify in localize_BT_RPi.py, scan_BT_RPi.py (includes the Server IP & PORT)
* If using ESP32s, reserve IPs and modify them in code as well

### Install libraries
* sudo python3 -m pip install pybluez
* sudo apt-get install bluetooth libbluetooth-dev

### Copy over the following files to RPi devices
* localize_BT_RPi.py: Raspberry Pi Bluetooth Localization Script
    * Run on a single RPi control node (open separate terminal)
    * Command: python3 localize_BT_RPi.py
* scan_BT_RPi.py: Raspberry Pi Bluetooth Scanning Script
    * Run on both RPi control nodes
    * Command: sudo python3 scan_BT_RPi.py

## Running Bluetooth Scanning Scripts on ESP32
* Modify WiFi SSID, PASS in wifi_setup.c 
* Reserve IPs for the ESP32s as needed, modify in localize_BT_RPi.py (on the RPi)
* Modify RPi Control Node (Server) IP and PORT in scan_BT_ESP32.c

### Setting up ESP-IDF development environment
* Install the build tools from [here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/windows-setup.html#get-started-windows-tools-installer)
* During the installation, install it in different directory than desktop
* Once installed, open command prompt shortcut specifically for ESP-IDF
* Change directory to the project path (top level), note that file path CANNOT have any spaces as the build tool is not compatible

### Building the code & monitoring serial output
* Clean build: idf.py fullclean
* Build command: idf.py build
    * Common error encountered with warning of "duplicate file", either rerun command until it works or clean build and try again
* Build + Flash: idf.py -p PORT flash
    * PORT will be COM5 for example
* Monitor serial port: idf.py -p PORT monitor

## References
* [Python AES Documentation](https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html)
* [RPi Bluetooth Scanning Starter Code](https://github.com/karulis/pybluez/blob/master/examples/advanced/inquiry-with-rssi.py)
* [ESP32 Wifi Connection Code](https://github.com/espressif/esp-idf/blob/master/examples/wifi/getting_started/station/main/station_example_main.c)
* [ESP32 Bluetooth Scanning Starter Code](https://github.com/espressif/esp-idf/blob/master/examples/bluetooth/bluedroid/classic_bt/bt_discovery/main/bt_discovery.c)
* ESP32 AES [Example 1](https://everythingesp.com/esp32-arduino-tutorial-encryption-aes128-in-ecb-mode/) [Example 2](https://tls.mbed.org/kb/how-to/encrypt-with-aes-cbc)
