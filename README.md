# Privacy Leak Detector

A static analysis tool for Android APKs to detect potential privacy leaks. It traces data flows from sensitive sources (like Location, SMS, Device ID) to exfiltration sinks (like Network, Logging, File System).

## 🚀 Features

- **APK Analysis**: Disassembles and analyzes Android APK files using `androguard`.
- **Leak Detection**: Identifies:
  - **Direct Leaks**: Sensitive data accessed and immediately sent to a sink in the same method.
  - **Indirect Leaks**: Sensitive data passed through method calls before reaching a sink (limited depth).
- **Comprehensive Reporting**: Generates reports in Text or JSON format.
- **SDK Detection**: Identifies if a leak originates from a third-party SDK or App code.

## 🛠️ Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/saicharan0810/privacy-leak-detector.git
    cd privacy-leak-detector
    ```

2.  **Set up a Virtual Environment** (Recommended):
    ```bash
    python3.12 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## 📖 Usage

Run the tool on an APK file:

```bash
python main.py path/to/app.apk
```

### Options

- `-f, --format [text|json]`: Choose output format (default: `text`).
- `-o, --output PATH`: Save report to a file instead of printing to stdout.

**Example**:
```bash
python main.py AndroGoat.apk --format json -o results.json
```

## 🧪 Testing

To run the unit tests:

```bash
python -m unittest tests/test_tracer.py
```

## ⚠️ Disclaimer

This tool is for educational and security testing purposes only. Use responsibly on applications you own or have permission to test.
