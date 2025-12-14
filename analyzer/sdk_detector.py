
KNOWN_SDKS = {
    "com.google.android.gms.ads": "Google AdMob",
    "com.facebook.ads": "Facebook Audience Network",
    "com.unity3d.ads": "Unity Ads",
    "com.ironhouse": "IronSource",
    "com.applovin": "AppLovin",
    "com.mopub": "MoPub",
    "com.adjust.sdk": "Adjust",
    "com.appsflyer": "AppsFlyer",
    "com.flurry": "Flurry Analytics",
    "com.google.firebase": "Firebase",
    "io.branch": "Branch.io",
}

def identify_sdk(class_name):
    """
    Returns the SDK name if the class matches a known SDK package, else None.
    Input should be in the format 'Lcom/example/package/Class;'
    """
    # Convert 'Lcom/example/...' to 'com.example...'
    clean_name = class_name.lstrip('L').replace('/', '.').rstrip(';')
    
    for prefix, sdk_name in KNOWN_SDKS.items():
        if clean_name.startswith(prefix):
            return sdk_name
    return None
