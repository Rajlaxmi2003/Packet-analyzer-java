# Windows setup

1. Install a JDK (version 17 or newer) and ensure `java` and `javac` are available in PowerShell.
2. Open PowerShell in the project directory.
3. Compile the project:

   ```powershell
   .\build.ps1
   ```

4. Run the DPI engine:

   ```powershell
   java -cp build\classes packetanalyzer.DpiMain test_dpi.pcap filtered.pcap
   ```

5. To use the webpage, start the local server:

   ```powershell
   java -cp build\classes packetanalyzer.WebMain
   ```

   Open `http://127.0.0.1:8765` in your browser. Choose the PCAP file, optionally enter blocking rules, and click **Analyze karein**. Press `Ctrl+C` in PowerShell to stop the server.

6. Or run the packet-summary reader:

   ```powershell
   java -cp build\classes packetanalyzer.PacketAnalyzerMain test_dpi.pcap 10
   ```

7. Regenerate the test capture when needed:

   ```powershell
   java -cp build\classes packetanalyzer.TestPcapGenerator
   ```

The project has no third-party dependencies, Python runtime, C++ compiler, or CMake requirement. See [README.md](./README.md) for blocking options, rule-file syntax, and implementation limitations.
