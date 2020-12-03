# Frida Tutorial: Android Sensor Injection

These days its quite common for android malware to perform a number of anti-emulation techniques to deter dynamic malware analysis. One of the more advanced techniques is performing calculations on sensor values returned from the accelerometer, gyroscope or GPS data. 

This tutorial will document some basic frida techniques to bypass sensor injection alongside android source code reversing. 


## Basic frida script setup

For every frida script this will generally be your basic format.


