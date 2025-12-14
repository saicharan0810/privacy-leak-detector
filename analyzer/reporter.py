import json
import os

class Reporter:
    def __init__(self, leaks):
        self.leaks = leaks

    def generate_report(self, output_format="text"):
        if output_format == "json":
            return self._to_json()
        else:
            return self._to_text()

    def _get_name_safe(self, method):
        if hasattr(method, 'get_name'): return str(method.get_name())
        return str(getattr(method, 'name', 'UnknownMethod'))

    def _get_class_name_safe(self, method):
        if hasattr(method, 'get_class_name'): return str(method.get_class_name())
        return str(getattr(method, 'class_name', 'UnknownClass'))

    def _to_json(self):
        # Convert objects to strings for JSON serialization
        serializable_leaks = []
        for leak in self.leaks:
            serializable_leaks.append({
                "type": leak['type'],
                "sdk": leak['sdk'],
                "source": {
                    "method": self._get_name_safe(leak['source']['method']),
                    "class": self._get_class_name_safe(leak['source']['method']),
                    "category": leak['source']['source'],
                    "api": leak['source']['callee']
                },
                "sink": {
                    "method": self._get_name_safe(leak['sink']['method']),
                    "class": self._get_class_name_safe(leak['sink']['method']),
                    "category": leak['sink']['sink'],
                    "api": leak['sink']['callee']
                }
            })
        return json.dumps(serializable_leaks, indent=2)

    def _to_text(self):
        lines = []
        lines.append("=== Privacy Leak Report ===")
        if not self.leaks:
            lines.append("No leaks detected based on current heuristics.")
            return "\n".join(lines)

        for i, leak in enumerate(self.leaks, 1):
            lines.append(f"\n[Leak #{i}] Type: {leak['type']}")
            lines.append(f"  SDK Context: {leak['sdk'] if leak['sdk'] else 'App Code'}")
            
            src = leak['source']
            lines.append(f"  SOURCE: {src['source']} data accessed")
            lines.append(f"    at {self._get_class_name_safe(src['method'])}->{self._get_name_safe(src['method'])}")
            lines.append(f"    via call to {src['callee']}")
            
            sink = leak['sink']
            lines.append(f"  SINK: sent to {sink['sink']}")
            lines.append(f"    at {self._get_class_name_safe(sink['method'])}->{self._get_name_safe(sink['method'])}")
            lines.append(f"    via call to {sink['callee']}")
            
        return "\n".join(lines)
