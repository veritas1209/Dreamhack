# ====== -3000.exe ORACLE v2 (creation-order, multi-input) ======
$src = "C:\Users\hajin\IT_Projects\hacking_study\dreamhack\811--3000-9\-3000.exe"   # <-- EDIT to your -3000.exe
if (!(Test-Path $src)) { Write-Host "ERROR set `$src"; exit }

$bodies = @'
{"K1": "Ik2zwEQHfwcepYyNGfB51YbmwxAscRuzOl8G5UBBBpiA84YrNbuBhOwc8fjOWOrOwd8S7Ba16j7pGLou3SHvV5utg79bg16qMTSl4f28gZl2CePvzZaqLXj4sxrvXFcqgGxKh1ZXfuBeCTt2nllZpKKgOAxMi63jOZgW82k", "K2": "9382DFFX1Kvzq2TQmNmClrKboZzu3g8Xi7cgR5C3BXd7U6Yb54hKjLPOBLULIggXgrjL5cyavh66wXylWX29cK9wZtvdphPfR7fgg1yWq4d55dWku6judfqO8U0s1K46nRx6eTT9zt1gjhgpnlaTuNfgX7rn4Ey0VuA60Mv", "AA": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "AB": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BB": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}
'@ | ConvertFrom-Json

Remove-Item -Recurse -Force C:\a, C:\orun -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path C:\a | Out-Null

foreach ($p in $bodies.PSObject.Properties) {
    $tag=$p.Name; $body=$p.Value
    $name = $body + ".exe"
    $full = "C:\a\" + $name
    Copy-Item -LiteralPath $src -Destination $full -Force
    $outdir = "C:\orun\" + $tag
    New-Item -ItemType Directory -Force -Path $outdir | Out-Null
    cmd /c "cd /d `"$outdir`" && `"$full`"" | Out-Null
    Write-Host ("##### TAG " + $tag + "  ARGV0=" + $full)
    Get-ChildItem -LiteralPath $outdir | Sort-Object CreationTime | ForEach-Object {
        $b=[System.IO.File]::ReadAllBytes($_.FullName)
        $hex = -join ($b | ForEach-Object { $_.ToString("x2") })
        $ticks = $_.CreationTime.Ticks
        Write-Host ($ticks.ToString() + " " + $_.Name + " " + $hex)
    }
    Write-Host "##### END $tag"
}
Write-Host "##### ALLDONE"
