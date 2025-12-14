from .definitions import SENSITIVE_SOURCES, EXFILTRATION_SINKS
from .sdk_detector import identify_sdk

class Tracer:
    def __init__(self, analysis_obj):
        self.analysis = analysis_obj
        self.sources_found = [] # List of (InternalMethod, SourceName, SDK)
        self.sinks_found = []   # List of (InternalMethod, SinkName, SDK)
        self.leaks = []         # List of dicts describing leaks

    def _match_method(self, method_obj, signatures):
        """
        Check if the method_obj matches any of the signatures.
        method_obj can be ExternalMethod or MethodAnalysis.
        """
        # We need the full name similarly to how we defined it: Lpkg/cls;->method
        # Androguard methods have .class_name, .name, .descriptor
        
        # Construct the signature string
        # method_obj.class_name might look like 'Ljava/util/List;'
        # method_obj.name is 'add'
        try:
            if hasattr(method_obj, 'get_class_name'):
                cls_name = str(method_obj.get_class_name())
            else:
                cls_name = str(getattr(method_obj, 'class_name', 'UnknownClass'))

            if hasattr(method_obj, 'get_name'):
                m_name = str(method_obj.get_name())
            else:
                m_name = str(getattr(method_obj, 'name', 'UnknownMethod'))
            
            full_sig = f"{cls_name}->{m_name}"
            
            for defined_sig, category in signatures.items():
                if full_sig == defined_sig:
                    return category
        except Exception as e:
            # print(f"Error matching method: {e}")
            pass
        return None

    def find_usages(self):
        """
        Find all internal methods that call Sources or Sinks.
        """
        print("Scanning for sensitive API usages...")
        
        for method in self.analysis.get_methods():
            if method.is_external():
                continue
            
            for _, callee, _ in method.get_xref_to():
                # Check if callee is a Source
                source_cat = self._match_method(callee, SENSITIVE_SOURCES)
                if source_cat:
                    self.sources_found.append({
                        "method": method,
                        "source": source_cat,
                        "callee": str(callee),
                        "sdk": identify_sdk(str(method.get_class_name()))
                    })

                # Check if callee is a Sink
                sink_cat = self._match_method(callee, EXFILTRATION_SINKS)
                if sink_cat:
                    self.sinks_found.append({
                        "method": method,
                        "sink": sink_cat,
                        "callee": str(callee),
                        "sdk": identify_sdk(str(method.get_class_name()))
                    })
        
        print(f"Found {len(self.sources_found)} source locations.")
        print(f"Found {len(self.sinks_found)} sink locations.")

    def analyze_reachability(self):
        """
        Check if data from Source usages flows to Sink usages.
        Strategy:
        1. Direct Leak: Same method calls Source then Sink.
        2. Indirect Leak: Method A calls Source, then calls Method B ... -> Sink.
        """
        
        for src_info in self.sources_found:
            src_method = src_info['method']
            src_sdk = src_info['sdk']
            
            # 1. Check Direct Leak (same method)
            for sink_info in self.sinks_found:
                if sink_info['method'] == src_method:
                    self.leaks.append({
                        "type": "Direct",
                        "source": src_info,
                        "sink": sink_info,
                        "sdk": src_sdk
                    })
            
            # 2. Check Indirect Leak (path in call graph)
            sink_callers = set([m['method'] for m in self.sinks_found])
            
            # BFS
            visited = set()
            # queue needs depth tracking: (method, depth)
            queue = [(src_method, 0)]
            visited.add(src_method)
            
            # Limit depth to avoid explosion
            max_depth = 10
            
            while queue:
                current_method, depth = queue.pop(0)
                
                if depth > max_depth:
                    continue
                
                # If current_method is a sink caller (and not the src_method itself, which we handled), add leak
                if current_method in sink_callers and current_method != src_method:
                     self.leaks.append({
                        "type": "Indirect (Depth {})".format(depth),
                        "source": src_info,
                        "sink": next(s for s in self.sinks_found if s['method'] == current_method),
                        "sdk": src_sdk 
                    })
                     break
                
                # Add callees
                for _, callee, _ in current_method.get_xref_to():
                     if not callee.is_external() and callee not in visited:
                         visited.add(callee)
                         queue.append((callee, depth + 1))
                         
    def get_results(self):
        return self.leaks

