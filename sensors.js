Java.perform(function() {

    // Basic Location hooks
    var lat = -25.298428;
    var lng = 110.131378;
    var Location = Java.use("android.location.Location");

    Location.getLatitude.implementation = function() {
        send("Overwriting Lat to " + lat);
        args.data = "getLattitude()  --> Overiding" + lat
        send(args);
        return lat;
    };

    Location.getLongitude.implementation = function() {
        send("Overwriting Lng to " + lng);
        args.data = "getLongitude()  --> Overiding" + lang
        send(args);
        return lng;
    };

    // Google Service needs to be implemented into another script. Throws an error if the APK isn't using services as dependency.
    /* var gService = Java.use('com.google.android.gms.common.GooglePlayServicesUtil');
     gService.isGooglePlayServicesAvailable.overload('android.content.Context').implementation = function () {
        return 0;
     };

     var gApiService = Java.use('com.google.android.gms.common.GoogleApiAvailability');
     gApiService.isGooglePlayServicesAvailable.overload('android.content.Context').implementation = function () {
         return 0;
     };

  Google Services Fused Location Provider
    var fusedLoc = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
     fusedLoc.getLastLocation.overload().implementation = function () {
     send('GetLastLocation');
     var task = Java.use('com.google.android.gms.tasks.Task')
     return task.$new();
    };
    */


    /* Storing sensor and handle as an object in an array to prevent unnecessary spam in output. Check for their existence, else send message.
       De-registering hook removes them from the object array so new handles can be printed.
       Using name -> handle allows multiple registered listeners to the same sensor without causing issues.
    */
    var systemSensorManager = Java.use('android.hardware.SystemSensorManager');
    var sensorEventQueue = Java.use('android.hardware.SystemSensorManager$SensorEventQueue');
    function aSensor(name, handle, listener) {
        this.name = name;
        this.listener = listener;
        this.handle = handle;
        this.getName = function() {
            return this.name
        }
        this.getHandle = function() {
            return this.handle;
        }
    }

    var sensorListeners = []

    systemSensorManager.registerListenerImpl.overload('android.hardware.SensorEventListener', 'android.hardware.Sensor',
        'int', 'android.os.Handler', 'int', 'int').implementation = function(listener, sensor, delay, handler, Latency, reservedFlags) {
        if (sensor != null) {
            // If array is empty - First sensor register
            if (sensorListeners.length <= 0) {
                var newSensor = new aSensor(sensor.getName(), sensor.getHandle(), listener)
                sensorListeners.push(newSensor)
                args.data = "registering a listener to : " + sensor.getName() + " with handle: " + sensor.getHandle() + " to class: " + listener.$className;
                send(args)
            }

            // Checking to see whether sensor has already been registered with handler, else send message.
            for (var x = 0; x < sensorListeners.length; x++) {
                if (sensor.getName() == sensorListeners[x].getName()) {
                    break;
                }

                // If final item in arraylist != current senor object, push sensor and send message
                if (x == sensorListeners.length - 1 && sensorListeners[x].getName() !== sensor.getName() && sensor.getHandle() !== sensorListeners[x].getHandle()) {
                    var newSensor = new aSensor(sensor.getName(), sensor.getHandle(), listener)
                    sensorListeners.push(newSensor)
                    args.data = "registering a listener to : " + sensor.getName() + " with handle: " + sensor.getHandle() + " to class: " + listener.$className;
                    send(args)
                }
            }
            return this.registerListenerImpl.call(this, listener, sensor, delay, handler, Latency, reservedFlags);
        } else {
            return this.registerListenerImpl.call(this, listener, sensor, delay, handler, Latency, reservedFlags);
        }
    }

    var injectionHandles = []
    var accelSensor = 'Goldfish 3-axis Accelerometer'
    var newSensorValue = 10; // Change this to adjust all other sensor static values.
    var accelValue = 0; // Change this value to adjust accel sensor starting point
    var accelValues = [accelValue, accelValue, accelValue];

    sensorEventQueue.dispatchSensorEvent.overload('int', '[F', 'int', 'long').implementation = function(handle, values, accuracy, timestamp) {
        var existingInjection = false
        var newValues = [newSensorValue, newSensorValue, newSensorValue, newSensorValue, newSensorValue, newSensorValue, newSensorValue, newSensorValue]
        var isAccelSensor = false;
        var sendAccelMessage = false;
        // If injection array is empty, check accel sensor -> push else -> push
        if (injectionHandles.length <= 0) {
            checkForAccel(sensorListeners, handle, accelSensor, sendAccelMessage)
        }
        // Check if we've already printed for inject for sensor before ->  break;
        for (var x = 0; x < sensorListeners.length; x++) {
            if (handle.toString() == injectionHandles[x]) {
                existingInjection == true
                break;
            }
            // If we reach the end of the array and sensor/handle combo is new -> check for accel sensor -> push sensor handle/print -> else -> push sensor handle/print
            if (x == injectionHandles.length - 1 && handle.toString() !== injectionHandles[x] && existingInjection == false) {
                checkForAccel(sensorListeners, handle, accelSensor, sendAccelMessage)
            }
        }
        //Searching for accelSensor to send more realistic values
        for (var x = 0; x < sensorListeners.length; x++) {
            if (sensorListeners[x].name == accelSensor && sensorListeners[x].handle.toString() == handle.toString()) {
                isAccelSensor = true;
                break
            }
        }

        // if Accel sensor increment values
        if (isAccelSensor) {
            if(accelValues[0] == 100){
                accelValues[0]=accelValue
                accelValues[1]=accelValue
                accelValues[2]=accelValue
            }
            accelValues[0]+=1
            accelValues[1]+=1
            accelValues[2]+=1
            return this.dispatchSensorEvent(handle, accelValues, accuracy, timestamp)
        } else {
            return this.dispatchSensorEvent(handle, newValues, accuracy, timestamp)
        }
    }

    systemSensorManager.unregisterListenerImpl.overload('android.hardware.SensorEventListener', 'android.hardware.Sensor').implementation = function(listener, sensor) {
        if (sensor != null) {
            for (var x = 0; x < sensorListeners.length; x++) {
                if (sensorListeners[x].getHandle() == sensor.getHandle()) {
                    var tmpIndex = injectionHandles.indexOf(sensor.getHandle().toString())

                    // Removing from injection array & sensorListeners
                    if (tmpIndex > -1) {
                        injectionHandles.splice(tmpIndex, 1)
                    };
                    sensorListeners.splice(x, 1);
                    args.data = ("De-registering listener for sensor: " + sensor.getName() + " with handle: " + sensor.getHandle() + " to class: " + listener.$className)
                    send(args)
                    break
                }
            }
        }
        return this.unregisterListenerImpl(listener, sensor);
    }

    // Accel sensor sends a different message. Check whether event is for accel sensor & send message
    function checkForAccel(sensorListeners, handle, accelSensor, sendAccelMessage) {
        for (var x = 0; x < sensorListeners.length; x++) {
            if (sensorListeners[x].name == accelSensor && sensorListeners[x].handle.toString() == handle.toString()) {
                sendAccelMessage = true;
                break
            }
        }

        if (sendAccelMessage) {
            args.data = "Injecting sensor values to @handle: " + handle + " Values: Incrementing"
            send(args)
            injectionHandles.push(handle.toString())
        } else {
            args.data = "Injecting sensor values to @handle: " + handle + " Values: 10"
            send(args)
            injectionHandles.push(handle.toString())
        }
    }


    /* Setting timeout to find instance of sensorManager.
         setTimeout(function () {
         Java.perform(function () {
         var sensorManagerInstance = null;
         var counter = 0;

         while(sensorManagerInstance==null){

                  Java.choose('android.hardware.SystemSensorManager', {
                      onMatch: function(instance) {
                          sensorManagerInstance = instance;
                          send("Found instance: " + instance)
                      },
                      onComplete: function() {send('Finished Heap Search \n count: ' + counter)}
                  });
                  counter++;
          }

          var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          var sensorSystemManagerService = context.getSystemService("sensor");
          var sensor_manager = Java.cast(sensorSystemManagerService, Java.use('android.hardware.SensorManager'));
          var sensorListObj = sensorManagerInstance.getFullSensorList();
          var sensorAvailList = Java.cast(sensorListObj, Java.use("java.util.ArrayList"))

          // If Sensors available
          if(sensor_manager.getDefaultSensor(1) != null)
          {
       /*     Seems either accel/gyro sensors do not support injection or event injection is only possible in android Q.
              Frida-server seems to have issues on android Q so could not confirm. Leaving this code here as it may be useful in future cases.

             var sensorInjectBool = sensorManagerInstance.initDataInjection(true);
             var sensorInjectImp = sensorManagerInstance.initDataInjectionImpl(true);
             var accelSensor = sensor_manager.getDefaultSensor(1).isDataInjectionSupported();
             send("Sensor injection supported: " + accelSensor);

              var values = [10, 10, 10];
              sensorManagerInstance.injectSensorData(sensor_manager.getDefaultSensor(1), values, 1, 12.00);

              {'type': 'error', 'description': 'Error: java.lang.IllegalArgumentException: sensor does not support data injection', 'stack': 'Error: java.lang.IllegalArgumentException: sensor does not support data injection\n

          }else
          {
              send("no sensor found");
          }
          });
         }, 3000)//3000 min
         */
});
