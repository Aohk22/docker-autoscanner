# docker-autoscanner
Scans file using various command line tools + VirusTotal

If you're on Windows please clone with:  
```powershell
git -c core.autocrlf=false clone https://github.com/Aohk22/docker-autoscanner.git
```

## Example workflow

### On host
```bash
chmod +x start.sh
./start.sh <image_id>
```
Copy malware files.  
```bash
cp /path/to/malware/sample.exe /path/to/docker-autoscanner/malware
```
Docker image contains 7z in case the sample is compressed.

### On container
```bash
cp /malware/sample.exe .
autoscan.sh sample.exe
```
If you want to use VirusTotal API
```bash
autoscan.sh -s <key> sample.exe
```
