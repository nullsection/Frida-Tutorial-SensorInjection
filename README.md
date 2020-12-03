# Frida Tutorial: Android Sensor Injection

These days its quite common for android malware to perform a number of anti-emulation techniques to deter dynamic malware analysis. One of the more advanced techniques is performing calculations on sensor values returned from the accelerometer, gyroscope or GPS data. A good example of this is the Anubis malware.

This tutorial will document some basic frida techniques to bypass sensor injection alongside android source code reversing. 




## Basic frida script setup

For every frida script this will generally be your basic format. I won't cover how to set up your AVD with frida-server or adb commands as that is well documented elsewhere. In this example I'll be using a test APK that I made that is located in the /APK/ of this project. 

###### fridaScript.py
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


###### Sensors.js
```
Java.perform(function() {
send("Smokescreen!")



});


```

###### Sensor apk

This APK I wrote testing the accelerometer, gyro and gps values. Writing your own apps and testing it with frida gives you a deeper understanding of how the internals of android source code works. I would encourage anyone learning frida with android to atleast the fundamentals of android applications. Android dev documentation for Java is quite good.

For the scope of this tutorial we will only look at motion sensor data manipluation, however the app handles gps. Reverse and inject at will! 

Here is the usage for sensors according to android: https://developer.android.com/guide/topics/sensors/sensors_motion#java

My accelerometer and gyro source code snippets for this application. 
 
```

  sensorManager = (SensorManager) getSystemService(SENSOR_SERVICE);
  gyroSensor = sensorManager.getDefaultSensor(Sensor.TYPE_GYROSCOPE);
  accelSensor = sensorManager.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
  sensorManager.registerListener(this, accelSensor, SensorManager.SENSOR_DELAY_NORMAL);
  
  
   int counter = 0;
    @Override
    public final void onSensorChanged(SensorEvent event) {

        sensorManager = (SensorManager) getSystemService(Context.SENSOR_SERVICE);

        float x = event.values[0];
        float y = event.values[1];
        float z = event.values[2];
        String xAxis = event.sensor.getName() +"\nX axis: " + String.valueOf(x) + "\n";
        String yAxis = "Y axis: " + String.valueOf(y) + "\n";
        String zAxis = "Z axis: " + String.valueOf(z) + "\n";

        TextView text = findViewById(R.id.textBuild);
        text.setText(xAxis + yAxis + zAxis);


        if(counter == 100){sensorManager.unregisterListener(this, accelSensor);}
        if(counter == 200){sensorManager.registerListener(this, accelSensor, SensorManager.SENSOR_DELAY_NORMAL);}
        if(counter == 250){sensorManager.unregisterListener(this, accelSensor);}
        
        // Automatically deregister listeners on event count and re-register. Useful for testing hooks within the register method.

        counter++;

    }


```








