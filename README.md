# WProject
WProject is a high-level automated web vulnerability scanner

Still in Development

Install:
```
git clone https://github.com/x0root/WProject.git
cd WProject
pip install -r requirements.txt
python3 install.py
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Run:
```
python3 main.py target.com --auto
```

Made by x0root
