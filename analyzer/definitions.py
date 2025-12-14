# Sources: Methods that return sensitive data
SENSITIVE_SOURCES = {
    "Landroid/location/LocationManager;->getLastKnownLocation": "LOCATION",
    "Landroid/location/LocationManager;->requestLocationUpdates": "LOCATION",
    "Landroid/location/Location;->getLatitude": "LOCATION",
    "Landroid/location/Location;->getLongitude": "LOCATION",
    "Landroid/telephony/TelephonyManager;->getDeviceId": "DEVICE_ID",
    "Landroid/telephony/TelephonyManager;->getImei": "DEVICE_ID",
    "Landroid/telephony/TelephonyManager;->getSimSerialNumber": "DEVICE_ID",
    "Landroid/os/Build;->getSerial": "DEVICE_ID",
    "Landroid/provider/Settings$Secure;->getString": "ANDROID_ID", # context checked dynamically often, but good heuristic
    "Landroid/content/ContentResolver;->query": "CONTACTS_OR_SMS", # Broad, need to check arguments usually, but basic check for now
}

# Sinks: Methods that send data out or log it
EXFILTRATION_SINKS = {
    "Ljava/net/URL;->openConnection": "NETWORK",
    "Ljava/net/HttpURLConnection;->connect": "NETWORK",
    "Ljava/net/HttpURLConnection;->getOutputStream": "NETWORK",
    "Lorg/apache/http/impl/client/DefaultHttpClient;->execute": "NETWORK",
    "Landroid/util/Log;->d": "LOGGING",
    "Landroid/util/Log;->e": "LOGGING",
    "Landroid/util/Log;->i": "LOGGING",
    "Landroid/util/Log;->v": "LOGGING",
    "Landroid/util/Log;->w": "LOGGING",
    "Ljava/io/FileOutputStream;->write": "FILE_SYSTEM",
    "Landroid/telephony/SmsManager;->sendTextMessage": "SMS",
    "Landroid/telephony/SmsManager;->sendMultipartTextMessage": "SMS",
    "Landroid/webkit/WebView;->loadUrl": "WEBVIEW",
    "Landroid/webkit/WebView;->postUrl": "WEBVIEW",
    "Landroid/webkit/WebView;->evaluateJavascript": "WEBVIEW",
    "Ljava/io/OutputStream;->write": "IO_WRITE",
}
