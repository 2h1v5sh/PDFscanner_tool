rule Detect_JavaScript
{
    meta:
        description = "Detects embedded JavaScript in PDF files"
        type = "JavaScript"
    strings:
        $js1 = /\/JavaScript/i
        $js2 = /\/JS/i
        $js3 = /\/AA\s*<<\s*\/O\s*<<\s*\/S\s*\/JavaScript\s*\/JS\s*\(/i
        $js4 = /app\.alert/i
        $js5 = /this\.execute/i
        $js6 = /this\.print/i
        $js7 = /this\.saveAs/i
        $js8 = /util\.printd/i
        $js9 = /app\.setTimeOut/i
        $js10 = /event\.target/i
    condition:
        $js1 or $js2 or $js3 or $js4 or $js5 or $js6 or $js7 or $js8 or $js9 or $js10
}

rule Detect_Launch_Action
{
    meta:
        description = "Detects Launch actions in PDF files"
        type = "Launch"
    strings:
        $launch1 = /\/Launch/i
        $launch2 = /\/Action\s*>>\s*\/Type\s*\/Action/i
        $launch3 = /\/S\s*\/Launch/i
        $launch4 = /\/Launch\s*<<\s*\/S\s*\/Launch/i
        $launch5 = /\/Launch\s*<<\s*\/F\s*<<\s*\/S\s*\/Launch/i
        $launch6 = /\/Launch\s*\/F\s*\(/i
        $launch7 = /\/Launch\s*<<\s*\/F\s*\(/i
        $launch8 = /\/Launch\s*<<\s*\/Win\s*\(/i
        $launch9 = /\/Launch\s*<<\s*\/Mac\s*\(/i
        $launch10 = /\/Launch\s*\/Win\s*\(/i
    condition:
        $launch1 or $launch2 or $launch3 or $launch4 or $launch5 or $launch6 or $launch7 or $launch8 or $launch9 or $launch10
}

rule Detect_OpenAction
{
    meta:
        description = "Detects OpenAction in PDF files"
        type = "OpenAction"
    strings:
        $openAction1 = /\/OpenAction/i
        $openAction2 = /\/AA/i
        $openAction3 = /\/OpenAfterSave/i
        $openAction4 = /\/OpenDocument/i
        $openAction5 = /\/Open/i
        $openAction6 = /\/O\s*<<\s*\/S\s*\/JavaScript\s*\/JS\s*\(/i
        $openAction7 = /\/O\s*<<\s*\/S\s*\/JavaScript\s*\/JS/i
        $openAction8 = /\/O\s*<<\s*\/JS\s*\(/i
        $openAction9 = /\/O\s*<<\s*\/JS/i
        $openAction10 = /\/Open\s*<<\s*\/JavaScript\s*\/JS\s*\(/i
    condition:
        $openAction1 or $openAction2 or $openAction3 or $openAction4 or $openAction5 or $openAction6 or $openAction7 or $openAction8 or $openAction9 or $openAction10
}

rule Detect_Embedded_Files
{
    meta:
        description = "Detects embedded files in PDF files"
        type = "EmbeddedFile"
    strings:
        $embed1 = /\/EmbeddedFile/i
        $embed2 = /\/FileAttachment/i
        $embed3 = /\/Type\s*\/EmbeddedFile/i
        $embed4 = /\/EF\s*<<\s*\/F\s*<<\s*\/Type\s*\/EmbeddedFile/i
        $embed5 = /\/EmbeddedFile\s*<<\s*\/Type\s*\/EmbeddedFile/i
        $embed6 = /\/Filespec\s*<<\s*\/EF\s*<<\s*\/F\s*<<\s*\/Type\s*\/EmbeddedFile/i
        $embed7 = /\/EmbeddedFile\s*\/Filespec/i
        $embed8 = /\/EmbeddedFile\s*\/Names/i
        $embed9 = /\/EmbeddedFile\s*\/Names\s*<<\s*\/Type\s*\/EmbeddedFile/i
        $embed10 = /\/EmbeddedFile\s*\/Names\s*<<\s*\/Type\s*\/EmbeddedFile\s*\/Filespec/i
    condition:
        $embed1 or $embed2 or $embed3 or $embed4 or $embed5 or $embed6 or $embed7 or $embed8 or $embed9 or $embed10
}

rule Detect_Shellcode
{
    meta:
        description = "Detects suspicious shellcode patterns in PDF files"
        type = "Shellcode"
    strings:
        $shellcode1 = { 6a 60 68 63 61 6c 63 54 59 66 83 e9 ff 33 d2 64 8b 52 30 8b 52 0c 8b 52 14 8b 72 28 }
        $shellcode2 = { 31 c0 50 68 2e 65 78 65 68 63 61 6c 63 8b dc 88 04 24 50 53 51 52 83 ec 04 }
        $shellcode3 = { 50 51 52 56 57 53 89 e5 83 e4 f0 31 c0 64 8b 40 30 8b 40 0c 8b 70 1c ad 8b 40 08 }
        $shellcode4 = { 89 e5 81 ec a0 00 00 00 31 c0 50 50 50 50 40 89 e1 50 89 e2 57 51 52 50 83 ec 04 }
        $shellcode5 = { 31 c0 50 68 2e 64 61 74 61 68 5c 64 61 74 61 68 63 61 6c 63 89 e3 8b 53 3c }
        $shellcode6 = { 31 d2 52 68 78 2e 74 78 68 2e 64 61 74 68 5c 5c 5c 68 2e 5c 5c 5c 68 5c 5c 5c }
        $shellcode7 = { 68 5c 61 5c 61 5c 61 68 74 2e 74 78 68 2e 64 61 74 68 5c 5c 5c 68 2e 5c 5c 5c }
        $shellcode8 = { 68 5c 61 5c 61 5c 61 68 78 2e 74 78 68 2e 64 61 74 68 5c 5c 5c 68 2e 5c 5c 5c }
        $shellcode9 = { 68 61 5c 61 5c 68 61 5c 68 74 2e 78 68 2e 61 74 68 5c 5c 68 2e 5c 68 5c 5c }
        $shellcode10 = { 68 61 5c 61 5c 61 68 74 2e 74 68 2e 64 68 5c 5c 5c 68 2e 5c 5c 68 5c 5c 68 }
    condition:
        $shellcode1 or $shellcode2 or $shellcode3 or $shellcode4 or $shellcode5 or $shellcode6 or $shellcode7 or $shellcode8 or $shellcode9 or $shellcode10
}

rule Detect_URLs
{
    meta:
        description = "Detects suspicious URLs in PDF files"
        type = "URL"
    strings:
        $url1 = /http[s]?:\/\/[^\s]+/ nocase
        $url2 = /ftp:\/\/[^\s]+/ nocase
        $url3 = /file:\/\/[^\s]+/ nocase
        $url4 = /:\/\/\w+\.\w+\.\w+/ nocase
        $url5 = /:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ nocase
        $url6 = /:\/\/\w+\.\w+\/[^\s]+/ nocase
        $url7 = /:\/\/[^\s]+\.\w+\/[^\s]+/ nocase
        $url8 = /[a-zA-Z0-9][-a-zA-Z0-9]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,6}/ nocase
        $url9 = /http:\/\/[^\s]+/ nocase
        $url10 = /https:\/\/[^\s]+/ nocase
    condition:
        $url1 or $url2 or $url3 or $url4 or $url5 or $url6 or $url7 or $url8 or $url9 or $url10
}
