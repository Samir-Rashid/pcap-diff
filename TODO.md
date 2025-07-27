- cool to be able to give two commit hashes and it compares pcap of the test run
    - give the pytest command and hashes, it runs and collects wireshark captures

- Add PyInstaller bundling option for creating standalone executables
    - Install PyInstaller in dev environment
    - Create build script with: `pyinstaller --onefile --name pcap-diff src/pcap_diff/main.py`
    - Results in single executable in dist/ folder


https://nix.dev/manual/nix/2.22/command-ref/new-cli/nix3-bundle
