1..3 | ForEach-Object {
    $ms = (Measure-Command {
        $c = New-Object Net.Sockets.TcpClient
        $c.Connect('127.0.0.1', 2222)
        $s = $c.GetStream()
        $b = New-Object byte[] 64
        [void]$s.Read($b, 0, 64)
        $c.Close()
    }).TotalMilliseconds
    "{0:N0} ms" -f $ms
}
