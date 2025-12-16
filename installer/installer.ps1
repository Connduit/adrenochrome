# loads reflectivedll.dll into memory and calls the reflectivedll.dll's reflectiveLoader function

Write-Host "[*] Starting DLL load test..." -ForegroundColor Cyan
Write-Host "[*] Target DLL path: $path" -ForegroundColor Cyan

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Native {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
}
"@

# Set your DLL path
$path = "C:\Users\Connor\Documents\Code\C++\adrenochrome\x64\Debug\installer.dll"

Write-Host "[*] Calling LoadLibrary..." -ForegroundColor Yellow
$hMod = [Native]::LoadLibrary($path)

if ($hMod -eq [IntPtr]::Zero) {
    $err = [Native]::GetLastError()
    Write-Host "[!] LoadLibrary FAILED." -ForegroundColor Red
    Write-Host "    Win32 Error Code: $err" -ForegroundColor Red

    try {
        $msg = (New-Object ComponentModel.Win32Exception($err)).Message
        Write-Host "    Error Message: $msg" -ForegroundColor Red
    } catch {
        Write-Host "    Could not decode error message." -ForegroundColor Red
    }
}
else {
    Write-Host "[+] LoadLibrary SUCCESS!" -ForegroundColor Green
    Write-Host "    Module Handle: $hMod" -ForegroundColor Green
}

Write-Host "[*] Completed." -ForegroundColor Cyan

