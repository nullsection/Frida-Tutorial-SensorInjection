# Frida Tutorial: Android Sensor Injection

These days its quite common for android malware to perform a number of anti-emulation techniques to deter dynamic malware analysis. One of the more advanced techniques is performing calculations on sensor values returned from the accelerometer, gyroscope or GPS data. 

This tutorial will document some basic frida techniques to bypass sensor injection alongside android source code reversing. 




## Basic frida script setup

For every frida script this will generally be your basic format. I won't cover how to set up your AVD with frida-server as that is well documented elsewhere. In this example I'll be using a test APK that I made that is located in the /APK/ of this project. 

###fridaScript.py
```
import frida
import os
import sys
import time

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device()
pid = device.spawn(["com.example.sensor"]) #PackageName
session = device.attach(pid)
f = open("C:../../Sensors.js")
script = session.create_script(f.read())
script.on('message', on_message)
script.load()
time.sleep(1)  # fails without this sleep
device.resume(pid)
sys.stdin.read()
```


###Sensors.js
```
Java.perform(function() {
send("Smokescreen!")



});


```
