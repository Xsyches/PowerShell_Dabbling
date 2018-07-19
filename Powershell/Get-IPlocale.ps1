# Extract an IP address from a string and return it.  Return $Null if no valid address found.
# (If the string contains more than one valid address only the first one will be returned)
Function ExtractValidIPAddress($String){
    $IPregex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’ 
    If ($String -Match $IPregex) {$Matches.Address}
}

$a = @(Get-content C:\Users\A048934\Desktop\xmas2.txt
foreach($i in $a){ExtractValidIPAddress $i}); 
$b = $a | Where-Object {$_ -match "Source IP:"} | Select-Object -Unique 
    $b = $b.Trim("Source IP: ") | Out-File C:\Users\A048934\Desktop\xmas2.txt -Append;
$c = gc C:\Users\A048934\Desktop\xmas2.txt
foreach($i in $c){
Get-IPGeolocation $i | Export-Csv -Path C:\Users\A048934\Desktop\xmas2.csv -Append 
}

$excel = New-Object -ComObject excel.application
$excel.visible = $True
$workbook = $excel.Workbooks.Add()
$uregwksht=$workbook.Worksheets(1)
$uregwksht.Name = 'Xmas IPs'
$uregwksht.Cells.Item(1,1)='Latitude'
$uregwksht.Cells.Item(1,2)='Longitude'
$uregwksht.Cells.Item(1,3)='IP'
$uregwksht.Cells.Item(1,4)='City'
$uregwksht.Cells.Item(1,5)='CountryName'
$records = Import-Csv -Path C:\Users\A048934\Desktop\xmas2.csv | Sort-Object "CountryName" 
$i = 2
foreach($record in $records) {
$excel.cells.item($i,1) = $record.Latitude
$excel.cells.item($i,2) = $record.Longitude
$excel.cells.item($i,3) = $record.IP
$excel.cells.item($i,4) = $record.City
$excel.cells.item($i,5) = $record.CountryName
$i++
}
#add a filter to the columns
$headerRange = $excel.Range("a1","e1")
$headerRange.AutoFilter() | Out-Null

#freeze the top row
$excel.Rows.Item("2:2").Select()
$excel.ActiveWindow.FreezePanes = $true

#adjusting the column width so all data is properly visible
$usedRange = $uregwksht.UsedRange
$usedRange.EntireColumn.AutoFit() | Out-Null



