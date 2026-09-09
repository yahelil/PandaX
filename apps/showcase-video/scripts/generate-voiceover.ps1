$ErrorActionPreference = 'Stop'

$output = Join-Path $PSScriptRoot '..\public\audio\pandax-voiceover.wav'
New-Item -ItemType Directory -Force -Path (Split-Path $output) | Out-Null
$script = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'narration.txt') -Raw
$voice = New-Object -ComObject SAPI.SpVoice
$stream = New-Object -ComObject SAPI.SpFileStream
$stream.Open($output, 3, $false)
$voice.AudioOutputStream = $stream
$voice.Rate = -1
$voice.Volume = 100
[void]$voice.Speak($script)
$stream.Close()
Write-Output "Generated $output"
