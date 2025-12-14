import unittest
from analyzer.tracer import Tracer
from analyzer.definitions import SENSITIVE_SOURCES, EXFILTRATION_SINKS

class MockMethod:
    def __init__(self, class_name, name, is_ext=False):
        self.class_name = class_name
        self.name = name
        self.is_ext = is_ext
        self.xrefs = [] # List of MockMethod objects

    def get_class_name(self):
        return self.class_name

    def get_name(self):
        return self.name
    
    def is_external(self):
        return self.is_ext

    def add_call(self, other_method):
        # internal android xref structure is (Class, Method, offset)
        self.xrefs.append((None, other_method, 0))

    def get_xref_to(self):
        return self.xrefs
    
    def __str__(self):
        return f"{self.class_name}->{self.name}"
    
    def __repr__(self):
        return self.__str__()

class MockAnalysis:
    def __init__(self, methods):
        self.methods = methods

    def get_methods(self):
        return self.methods

class TestTracer(unittest.TestCase):
    def test_direct_leak(self):
        # Setup Source and Sink External APIs
        # Source: Landroid/location/LocationManager;->getLastKnownLocation
        source_api = MockMethod("Landroid/location/LocationManager;", "getLastKnownLocation", is_ext=True)
        # Sink: Landroid/util/Log;->d
        sink_api = MockMethod("Landroid/util/Log;", "d", is_ext=True)
        
        # User Code: BadActivity->onCreate
        # Calls both
        bad_method = MockMethod("Lcom/example/BadActivity;", "onCreate")
        bad_method.add_call(source_api)
        bad_method.add_call(sink_api)
        
        analysis = MockAnalysis([bad_method, source_api, sink_api])
        tracer = Tracer(analysis)
        
        tracer.find_usages()
        tracer.analyze_reachability()
        results = tracer.get_results()
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['type'], "Direct")
        self.assertEqual(results[0]['source']['source'], "LOCATION")
        self.assertEqual(results[0]['sink']['sink'], "LOGGING")

    def test_indirect_leak(self):
        # Path: MethodA (calls Source) -> MethodB (calls Sink)
        
        source_api = MockMethod("Landroid/location/LocationManager;", "getLastKnownLocation", is_ext=True)
        sink_api = MockMethod("Ljava/net/HttpURLConnection;", "connect", is_ext=True)
        
        method_a = MockMethod("Lcom/example/Tracker;", "track")
        method_b = MockMethod("Lcom/example/Network;", "upload")
        
        # A calls source
        method_a.add_call(source_api)
        # A calls B
        method_a.add_call(method_b)
        # B calls sink
        method_b.add_call(sink_api)
        
        analysis = MockAnalysis([method_a, method_b, source_api, sink_api])
        tracer = Tracer(analysis)
        
        tracer.find_usages()
        tracer.analyze_reachability()
        results = tracer.get_results()
        
        self.assertEqual(len(results), 1)
        self.assertTrue("Indirect" in results[0]['type'])
        self.assertEqual(results[0]['source']['method'], method_a)
        self.assertEqual(results[0]['sink']['method'], method_b)

    def test_no_leak_disconnected(self):
        # MethodA calls source. MethodB calls sink. No link.
        source_api = MockMethod("Landroid/location/LocationManager;", "getLastKnownLocation", is_ext=True)
        sink_api = MockMethod("Ljava/net/HttpURLConnection;", "connect", is_ext=True)
        
        method_a = MockMethod("Lcom/example/Safe;", "getLocation")
        method_b = MockMethod("Lcom/example/Other;", "doNetwork")
        
        method_a.add_call(source_api)
        method_b.add_call(sink_api)
        
        analysis = MockAnalysis([method_a, method_b, source_api, sink_api])
        tracer = Tracer(analysis)
        
        tracer.find_usages()
        tracer.analyze_reachability()
        results = tracer.get_results()
        
        self.assertEqual(len(results), 0)

if __name__ == '__main__':
    unittest.main()
