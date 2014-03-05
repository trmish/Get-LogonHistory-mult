<#
Скрипт показывает недавнюю историю входа на любом компьютере Windows Server 2003/2008
.Description
    Этот скрипт просматривает Security Event Log и выдает сообщения интерактивного входа в систему. (локальный или удаленный rdesktop) и выход из системы
    
    Скрипт должен быть запущен с повышенными привелегиями и правами чтения Security Event Log на удаленой машине. (прим. Domain Admins) 
      
   

.Outputs
    System.Management.Automation.PSCustomObject
    
    Get-LogonHistory returns a custom object containing the following properties:
    
    [String]UserName
        The username of the account that logged on/off of the machine.
    [String]ComputerName
        The name of the computer that the user logged on to/off of.
    [String]Action
        The action the user took with regards to the computer. Either 'logon' or 'logoff'.
    [String]LogonType
        Either 'console' or 'remote', depending on how the user logged on. This property is null if the user logged off.
    [DateTime]TimeStamp
        A DateTime object representing the date and time that the user logged on/off.
.Notes
    
.Example
    .\Get-LogonHistory.ps1
    
    Description
    -----------
    Gets the available logon entries in the Security log on the local computer.
.Example
    Invoke-Command -ComputerName 'remotecomputer' -File '.\Get-LogonHistory.ps1'
    
    Description
    -----------
    Gets the available logon entries in the Security log on a remote computer named 'remotecomputer'.
#>


function Get-Win2008LogonHistory-en {
    $user=$null #обнуление переменной $user от возможного мусора предыдущего запуска скрипта
    $logons = Get-EventLog Security -computername $_ -AsBaseObject -InstanceId 4624 -after $date |
              Where-Object { ($_.Message -match "Logon Type:\s+2") `
                        -or  ($_.Message -match "Logon Type:\s+10") }
    
    $events = $logons  | Sort-Object TimeGenerated
    
    if ($events) {
        foreach($event in $events) {
            # Parse logon data from the Event (Поиск событий входа).
            if ($event.InstanceId -eq 4624) {
                # A user logged on (Пользователь залогинился).
                $action = 'logon'
                
                $event.Message -match "Logon Type:\s+(\d+)" | Out-Null
                $logonTypeNum = $matches[1]
                
                # Determine logon type (Определение типа входа).
                if ($logonTypeNum -eq 2) {
                    $logonType = 'console'
                } elseif ($logonTypeNum -eq 10) {
                    $logonType = 'remote'
                } else {
                    $logonType = 'other'
                }
                
                # Determine user (Определение пользователя).
                if ($event.message -match "New Logon:\s*Security ID:\s*.*\s*Account Name:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }
                
            } elseif ($event.InstanceId -eq 4647) {
                # A user logged off.
                $action = 'logoff'
                $logonType = $null

                
                # Determine user (Определение пользователя).
                if ($event.message -match "Subject:\s*Security ID:\s*.*\s*Account Name:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }
            } elseif ($event.InstanceId -eq 41) {
                # The computer crashed.
                $action = 'logoff'
                $logonType = $null
                $user = '*'
            }
         # Determine Account Domain (Определение домена пользователя).
                if ($event.message -match "Account Domain:\s*(\w+\S\w+\S\w+)") {
                    $UserDomain = $matches[1]
        
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }

            # As long as we managed to parse the Event, print output (После разбора лога фомируем наконец вывод).
            if ($user) {
                $aduser = Get-ADuser $user -Properties name, samaccountname, mail,telephonenumber | Select-Object name, samaccountname, mail, telephonenumber
                
                $timeStamp = Get-Date $event.TimeGenerated
                $output = New-Object -Type PSCustomObject
                Add-Member -MemberType NoteProperty -Name 'TimeStamp' -Value $timeStamp -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'UserName' -Value $user -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'User Domain' -Value $UserDomain -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $Event.MachineName -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Action' -Value $action -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'LogonType' -Value $logonType -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Mail' -Value $aduser.Mail -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Telephonenumber' -Value $aduser.telephoneNumber -InputObject $output
                
                Write-Output $output | FT
                
                $output  | ConvertTo-Html | Add-Content  C:\script\UserProperties.html
                $output | Export-Csv -Append -Path C:\script\getuser.csv -Encoding 'UTF8' -force
                
            }
             
        }
    } else {
        Write-Host "No recent logon/logoff events ( Не обнаружено свежих записей о событиях входа в журнале )."
    }
}

function Get-Win2003LogonHistory-en {
    $user=$null #обнуление переменной $user от возможного мусора предыдущего запуска скрипта
    $logons = Get-EventLog Security -computername $_ -AsBaseObject -InstanceId 528 -after $date |
              Where-Object {($_.Message -match "Logon Type:\s+2") `
                        -or  ($_.Message -match "Logon Type:\s+10") }
    #$poweroffs = Get-Eventlog System -AsBaseObject -InstanceId 41
    $events = $logons | Sort-Object TimeGenerated
    
    if ($events) {
        foreach($event in $events) {
            # Parse logon data from the Event (Поиск событий входа).
            if ($event.InstanceId -eq 528) {
                # A user logged on (Пользователь залогинился).
                $action = 'logon' 
                $event.Message -match "Logon Type:\s+(\d+)" | Out-Null
                $logonTypeNum = $matches[1]
                
                # Determine logon type (Определение типа входа).
                if ($logonTypeNum -eq 2) {
                    $logonType = 'console'
                } elseif ($logonTypeNum -eq 10) {
                    $logonType = 'remote'
                } else {
                    $logonType = 'other'
                }
                
                # Determine user (Определение пользователя).
                if ($event.message -match "Successful Logon:\s*User Name:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }
                
            } elseif ($event.InstanceId -eq 551) {
                # A user logged off.
                $action = 'logoff'
                $logonType = $null
                
                # Determine user (Определение пользователя).
                if ($event.message -match "User initiated logoff:\s*User Name:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                   
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }
            }

             # Determine Account Domain (Определение домена пользователя).
                if ($event.message -match "Domain:\s*(\w+\S\w+\S\w+)") {
                    $UserDomain = $matches[1]
        
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }
        
            # As long as we managed to parse the Event, print output (После разбора лога фомируем наконец вывод).

if ($User) {  
                $aduser = Get-ADuser $user -Properties name, samaccountname, mail,telephonenumber | Select-Object name, samaccountname, mail, telephonenumber
                
                $timeStamp = Get-Date $event.TimeGenerated
                $output = New-Object -Type PSCustomObject
                Add-Member -MemberType NoteProperty -Name 'TimeStamp' -Value $timeStamp -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'UserName' -Value $user -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'User Domain' -Value $UserDomain -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $Event.MachineName -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Action' -Value $action -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'LogonType' -Value $logonType -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Mail' -Value $aduser.Mail -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Telephonenumber' -Value $aduser.telephoneNumber -InputObject $output
                Write-output $output | FT 
                $output  | ConvertTo-Html | add-content C:\script\UserProperties.html
                $output | Export-Csv -Append -Path C:\script\getuser.csv -Encoding 'UTF8' -force
                Write-Host "."
                
            } 

        }
    } else {
        Write-Host "No recent logon/logoff events ( Не обнаружено свежих записей о событиях входа в журнале )."
    }
}

function Get-Win2008LogonHistory-ru {
    $user=$null #обнуление переменной $user от возможного мусора предыдущего запуска скрипта
    $logons = Get-EventLog Security -computername $_ -AsBaseObject -InstanceId 4624,4647 -after $date |
              Where-Object {($_.Message -match "Тип входа:\s+2") `
                        -or  ($_.Message -match "Тип входа:\s+10") }
    #$poweroffs = Get-EventLog System -AsBaseObject -InstanceId 41
    $events = $logons | Sort-Object TimeGenerated
    
    if ($events) {
        foreach($event in $events) {
        
            # Parse logon data from the Event (Поиск событий входа).
            if ($event.InstanceId -eq 4624) {
                # A user logged on (Пользователь залогинился).
                $action = 'logon'
                
                $event.Message -match "Тип входа:\s+(\d+)" | Out-Null
                $logonTypeNum = $matches[1]
                
                # Determine logon type (Определение типа входа).
                if ($logonTypeNum -eq 2) {
                    $logonType = 'console'
                } elseif ($logonTypeNum -eq 10) {
                    $logonType = 'remote'
                } else {
                    $logonType = 'other'
                }
                
                # Determine user (Определение пользователя).
                if ($event.message -match "Новый вход:\s*ИД безопасности:\s*.*\s*Имя учетной записи:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                } else {
                    $index = $event.index
                    Write-Warning "Не удалось разобрать журнал 'Безопасность'. Искаженная запись? Index: $index"
                }
                
            } elseif ($event.InstanceId -eq 4647) {
                # A user logged off.
                $action = 'logoff'
                $logonType = $null
                
                # Determine user (Определение пользователя).
                if ($event.message -match "Субъект:\s*ИД безопасности:\s*.*\s*Имя учетной записи:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                } else {
                    $index = $event.index
                    Write-Warning "Не удалось разобрать журнал 'Безопасность'. Искаженная запись? Index: $index"
                }
            } elseif ($event.InstanceId -eq 41) {
                # The computer crashed.
                $action = 'logoff'
                $logonType = $null
                $user = '*'
            }

             # Determine Account Domain (Определение домена пользователя).
                if ($event.message -match "Домен учетной записи:\s*(\w+\S\w+\S\w+)") {
                    $UserDomain = $matches[1]
        
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }
        
            # As long as we managed to parse the Event, print output.
            if ($user) {
                $aduser = Get-ADuser $user -Properties name, samaccountname, mail,telephonenumber | Select-Object name, samaccountname, mail, telephonenumber
                
                $timeStamp = Get-Date $event.TimeGenerated
                $output = New-Object -Type PSCustomObject
                Add-Member -MemberType NoteProperty -Name 'TimeStamp' -Value $timeStamp -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'UserName' -Value $user -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'User Domain' -Value $UserDomain -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $Event.MachineName -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Action' -Value $action -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'LogonType' -Value $logonType -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Mail' -Value $aduser.Mail -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Telephonenumber' -Value $aduser.telephoneNumber -InputObject $output
                
                Write-Output $output | FT
                $output  | ConvertTo-Html | Add-Content  C:\script\UserProperties.html
                $output | Export-Csv -Append -Path C:\script\getuser.csv -Encoding 'UTF8' -force
                
            }
             
        }
    } else {
        Write-Host "No recent logon/logoff events ( Не обнаружено свежих записей о событиях входа в журнале )."
    }
}

function Get-Win2003LogonHistory-ru {
    $user=$null #обнуление переменной $user от возможного мусора предыдущего запуска скрипта
    $logons = Get-EventLog Security -computername $_ -AsBaseObject -InstanceId 528 -after $date |
              Where-Object {($_.Message -match "Тип входа:\s+2") `
                        -or  ($_.Message -match "Тип входа:\s+10") }
    #$poweroffs = Get-Eventlog System -AsBaseObject -InstanceId 41
    $events = $logons  | Sort-Object TimeGenerated 
    
    if ($events) {
        foreach($event in $events) {
        
            # Parse logon data from the Event.
            if ($event.InstanceId -eq 528) {
                # A user logged on.
                $action = 'logon' 
                $event.Message -match "Тип входа:\s+(\d+)" | Out-Null
                $logonTypeNum = $matches[1]
                
                # Determine logon type.
                if ($logonTypeNum -eq 2) {
                    $logonType = 'console'
                } elseif ($logonTypeNum -eq 10) {
                    $logonType = 'remote'
                } else {
                    $logonType = 'other'
                }
                
                # Determine user.
                if ($event.message -match "Успешный вход в систему:\s*Пользователь:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                } else {
                    $index = $event.index
                    Write-Warning "Не удалось разобрать журнал 'Безопасность'. Искаженная запись? Index: $index"
                }
                
            } elseif ($event.InstanceId -eq 551) {
                # A user logged off.
                $action = 'logoff'
                $logonType = $null
                
                # Determine user.
                if ($event.message -match "Выход, вызванный пользователем:\s*Пользователь:\s*(\w+\S\w+\S\w+)") {
                    $user = $matches[1]
                   
                } else {
                    $index = $event.index
                    Write-Warning "Не удалось разобрать журнал 'Безопасность'. Искаженная запись? Index: $index"
                }
            }

             # Determine Account Domain (Определение домена пользователя).
                if ($event.message -match "Домен:\s*(\w+\S\w+\S\w+)") {
                    $UserDomain = $matches[1]
        
                } else {
                    $index = $event.index
                    Write-Warning "Unable to parse Security log Event. Malformed entry? Index: $index"
                }
        
        
            # As long as we managed to parse the Event, print output.

if ($User) {  
                $aduser = Get-ADuser $user -Properties name, samaccountname, mail,telephonenumber | Select-Object name, samaccountname, mail, telephonenumber
                
                $timeStamp = Get-Date $event.TimeGenerated
                $output = New-Object -Type PSCustomObject
                Add-Member -MemberType NoteProperty -Name 'TimeStamp' -Value $timeStamp -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'UserName' -Value $user -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'User Domain' -Value $UserDomain -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $Event.MachineName -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Action' -Value $action -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'LogonType' -Value $logonType -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Mail' -Value $aduser.Mail -InputObject $output
                Add-Member -MemberType NoteProperty -Name 'Telephonenumber' -Value $aduser.telephoneNumber -InputObject $output
                
                Write-output $output | FT 
                $output  | ConvertTo-Html | add-content C:\script\UserProperties.html
                $output | Export-Csv -Append -Path C:\script\getuser.csv -Encoding 'UTF8' -force
                
            } 

        }
    } else {
        Write-Host "No recent logon/logoff events ( Не обнаружено свежих записей о событиях входа в журнале )."
    }
}

Import-Module ActiveDirectory
$Date = $null
$Day = $null
$Day = Read-Host "Enter count of several last days for parse log ( Введите количество дней за которые надо собрать информацию из лога )"
$Date = (Get-Date).AddDays(-$Day)
$ComputerName = $Null
$ComputerName = Read-Host "Enter computer name for analysis ( Введите имя компьютера для анализа )"
#$ComputerName = (Import-Csv -Path C:\script\computers.csv).name 


 $ComputerName | ForEach-Object  { 


$OSversion = (Get-WmiObject -computername $_ -Query 'SELECT version FROM Win32_OperatingSystem').version
$OSLanguage = (Get-WmiObject -computername $_ -Query 'SELECT oslanguage FROM Win32_OperatingSystem').oslanguage

if (($OSversion -ge 6) -and ($OSLanguage -eq 1049))
{ "Сбор событий журнала Security на компьютере $_ (Windows 2008 RU)" 
    Get-Win2008LogonHistory-rus

} else {

if (($OSversion -ge 6) -and ($OSLanguage -eq 1033)) {
   "Сбор событий журнала Security на компьютере $_ (Windows 2008 EN)"
    Get-Win2008LogonHistory-en

}        elseif  ($OSLanguage -ge 1049) {
    "Сбор событий журнала Security на компьютере $_ (Windows 2003 RU)"
    Get-Win2003LogonHistory-rus
  }
  else {
    "Сбор событий журнала Security на компьютере $_ (Windows 2003 EN)"
    Get-Win2003LogonHistory-en
  }
 }
 }
 
 
  
 

 
 
