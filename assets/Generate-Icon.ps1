# Generates assets/icon.png — the NuGet package icon for both
# Argon2id.PasswordHasher and Argon2id.PasswordHasher.AspNetCore.
#
# Design: a 128x128 rounded-square in the project accent color (#7c3aed,
# matches the demo apps' UI accent) with a white padlock silhouette.
# Plain enough to remain legible at the 64x64 thumbnail nuget.org uses.
#
# To regenerate after editing this script:
#     pwsh -File assets/Generate-Icon.ps1
#
# Requires Windows PowerShell or pwsh 7+ on Windows (System.Drawing.Common
# is a Windows-only assembly outside Windows PowerShell).

Add-Type -AssemblyName System.Drawing

$outPath = Join-Path $PSScriptRoot 'icon.png'
$size    = 128

$bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Fully transparent background so the icon sits cleanly on any theme.
$g.Clear([System.Drawing.Color]::Transparent)

# ---- Rounded-square background ------------------------------------------
$radius = 22
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$d = $radius * 2
$path.AddArc(0,           0,           $d, $d, 180, 90)
$path.AddArc($size - $d,  0,           $d, $d, 270, 90)
$path.AddArc($size - $d,  $size - $d,  $d, $d, 0,   90)
$path.AddArc(0,           $size - $d,  $d, $d, 90,  90)
$path.CloseFigure()
$accent = [System.Drawing.ColorTranslator]::FromHtml('#7c3aed')
$bgBrush = New-Object System.Drawing.SolidBrush($accent)
$g.FillPath($bgBrush, $path)

# ---- Padlock shackle (top arc) ------------------------------------------
$shacklePen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 12)
$shacklePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$shacklePen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
# Arc centered horizontally, sitting above the body
$shackleX = 38
$shackleY = 26
$shackleW = 52
$shackleH = 52
$g.DrawArc($shacklePen, $shackleX, $shackleY, $shackleW, $shackleH, 180, 180)

# ---- Padlock body (rounded rect) ----------------------------------------
$bodyRadius = 8
$bodyX = 30
$bodyY = 60
$bodyW = 68
$bodyH = 50
$bodyPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$bd = $bodyRadius * 2
$bodyPath.AddArc($bodyX,                         $bodyY,                          $bd, $bd, 180, 90)
$bodyPath.AddArc($bodyX + $bodyW - $bd,          $bodyY,                          $bd, $bd, 270, 90)
$bodyPath.AddArc($bodyX + $bodyW - $bd,          $bodyY + $bodyH - $bd,           $bd, $bd, 0,   90)
$bodyPath.AddArc($bodyX,                         $bodyY + $bodyH - $bd,           $bd, $bd, 90,  90)
$bodyPath.CloseFigure()
$whiteBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$g.FillPath($whiteBrush, $bodyPath)

# ---- Keyhole on the body ------------------------------------------------
$keyholeColor = $accent
$keyholeBrush = New-Object System.Drawing.SolidBrush($keyholeColor)
# Circle for the keyhole top
$g.FillEllipse($keyholeBrush, 58, 74, 12, 12)
# Tapered slot below it
$slotPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$slotPath.AddPolygon(@(
    (New-Object System.Drawing.PointF(60, 84)),
    (New-Object System.Drawing.PointF(68, 84)),
    (New-Object System.Drawing.PointF(70, 100)),
    (New-Object System.Drawing.PointF(58, 100))
))
$g.FillPath($keyholeBrush, $slotPath)

# ---- Save ---------------------------------------------------------------
$bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
$bgBrush.Dispose()
$whiteBrush.Dispose()
$keyholeBrush.Dispose()
$shacklePen.Dispose()

Write-Output "Wrote $outPath ($([math]::Round((Get-Item $outPath).Length / 1KB, 1)) KB)"
