param(
    [int]$Port = 31337,
    [string]$OutputFile = "memory.dmp"
)

Write-Host "Listening on port $Port, writing to $OutputFile ..."

# Создаём слушателя
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
$listener.Start()
$client = $listener.AcceptTcpClient()
Write-Host "Connection from" $client.Client.RemoteEndPoint

# Настраиваем потоки
$stream = $client.GetStream()
$fs = [System.IO.File]::Create($OutputFile)

$buffer = New-Object byte[] 1048576  # 1 MB буфер
$total = 0

while (($bytesRead = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
    $fs.Write($buffer, 0, $bytesRead)
    $total += $bytesRead
    if ($total % (100*1024*1024) -lt 1048576) { # каждые ~100MB прогресс
        Write-Host ("Received {0:N0} MB..." -f ($total / 1MB))
    }
}

Write-Host "Finished. Total received: $($total/1MB) MB"

$fs.Close()
$stream.Close()
$client.Close()
$listener.Stop()
