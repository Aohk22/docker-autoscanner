rule WhitesnakeImports
{
    strings:
        // Type references
        $clipboard = "Clipboard" ascii wide
        //$clipboard_method = "GetDataObject" ascii wide
        $console    = "Console" ascii wide
        $base64    = "FromBase64String" ascii wide
        $env_mname  = "get_MachineName" ascii wide
        $env_nline  = "get_NewLine" ascii wide
        $env_osver  = "get_OSVersion" ascii wide
        $gzip       = "GZipStream" ascii wide
        $httplstn   = "HttpListener" ascii wide
        $rsaserviceprov     = "RSACryptoServiceProvider" ascii wide
        $file       = "File" ascii wide

        // Assembly references
        $mscorlib   = "mscorlib" ascii wide
        $system     = "System" ascii wide
        $kernel32   = "kernel32.dll" ascii wide

    condition:
        5 of ($clipboard, $console, $base64, $env_mname, $env_nline, $env_osver, $gzip, $httplstn, $rsaserviceprov, $file) and
        any of ($mscorlib, $system, $kernel32)
}

rule WhitesnakeXorInstruction
{
	strings:
        $xor_full = { FE 0C 01 00 FE 0C 03 00 61 D1 FE 0E 05 00 28 1F 00 00 0A 28 20 00 00 0A FE 0E 01 00 }
		$xor = { FE 0C ?? 00 FE 0C ?? 00 FE 0C ?? 00 61 D1 }

	condition:
		$xor_full or $xor
}
