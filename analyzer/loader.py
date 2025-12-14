from androguard.misc import AnalyzeAPK
import sys

class APKLoader:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.dvm = None
        self.analysis = None

    def load(self):
        print(f"Loading APK: {self.apk_path}...")
        try:
            self.apk, self.dvm, self.analysis = AnalyzeAPK(self.apk_path)
            print("APK loaded successfully.")
            return True
        except Exception as e:
            print(f"Error loading APK: {e}")
            return False

    def get_package_name(self):
        if self.apk:
            return self.apk.get_package()
        return None
