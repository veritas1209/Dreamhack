# ====== -3000.exe ORACLE SCRIPT (run in PowerShell) ======
# EDIT THIS: full path to your original -3000.exe
$src = "C:\Users\hajin\IT_Projects\hacking_study\dreamhack\811--3000-9\-3000.exe"

if (!(Test-Path $src)) { Write-Host "ERROR: set `$src to the real -3000.exe path"; exit }

$name1 = "Ik2zwEQHfwcepYyNGfB51YbmwxAscRuzOl8G5UBBBpiA84YrNbuBhOwc8fjOWOrOwd8S7Ba16j7pGLou3SHvV5utg79bg16qMTSl4f28gZl2CePvzZaqLXj4sxrvXFcqgGxKh1ZXfuBeCTt2nllZpKKgOAxMi63jOZgW82k.exe"
$name2 = "9382DFFX1Kvzq2TQmNmClrKboZzu3g8Xi7cgR5C3BXd7U6Yb54hKjLPOBLULIggXgrjL5cyavh66wXylWX29cK9wZtvdphPfR7fgg1yWq4d55dWku6judfqO8U0s1K46nRx6eTT9zt1gjhgpnlaTuNfgX7rn4Ey0VuA60Mv.exe"

# clean+make dirs
Remove-Item -Recurse -Force C:\a, C:\out1, C:\out2 -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path C:\a, C:\out1, C:\out2 | Out-Null

Copy-Item -LiteralPath $src -Destination (Join-Path C:\a $name1) -Force
Copy-Item -LiteralPath $src -Destination (Join-Path C:\a $name2) -Force

function DumpRun($outdir, $name) {
    $full = "C:\a\" + $name
    # invoke via cmd so argv[0] == the exact full path string
    cmd /c "cd /d `"$outdir`" && `"$full`"" | Out-Null
    Write-Host "=== ARGV0: $full"
    Get-ChildItem -LiteralPath $outdir | Sort-Object Name | ForEach-Object {
        $b = [System.IO.File]::ReadAllBytes($_.FullName)
        $hex = -join ($b | ForEach-Object { $_.ToString("x2") })
        Write-Host ($_.Name + "=" + $hex)
    }
    Write-Host "=== END ($($(Get-ChildItem -LiteralPath $outdir).Count) files)"
}

Write-Host "########## RUN1 ##########"
DumpRun "C:\out1" $name1
Write-Host "########## RUN2 ##########"
DumpRun "C:\out2" $name2
Write-Host "########## DONE ##########"
