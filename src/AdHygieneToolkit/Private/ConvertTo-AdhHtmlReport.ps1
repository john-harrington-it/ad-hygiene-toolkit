function ConvertTo-AdhHtmlReport {
    <#
    .SYNOPSIS
        Renders audit sections into a single self-contained HTML report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Section,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Parameter,

        [string]$Title = 'Active Directory Hygiene Report'
    )

    $enc = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }
    $fmt = {
        param($v)
        if ($null -eq $v) { return '' }
        if ($v -is [datetime]) { return $v.ToString('yyyy-MM-dd') }
        if ($v -is [bool]) { if ($v) { return 'Yes' } else { return 'No' } }
        return [string]$v
    }

    $sb = New-Object -TypeName System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine(('<title>{0}</title>' -f (& $enc $Title)))
    [void]$sb.AppendLine(@'
<style>
:root{--bg:#0f172a;--panel:#111c33;--line:#22304d;--text:#e2e8f0;--muted:#94a3b8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;--accent:#38bdf8}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
header{padding:28px 32px;border-bottom:1px solid var(--line)}h1{margin:0 0 4px;font-size:22px}h2{font-size:17px;margin:0 0 12px}
.meta{color:var(--muted);font-size:13px}main{padding:24px 32px;max-width:1400px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:28px}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--ok);border-radius:10px;padding:14px 16px}
.card.warn{border-left-color:var(--warn)}.card .n{font-size:28px;font-weight:700}.card .l{color:var(--muted)}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:22px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--accent);font-weight:600;position:sticky;top:0;background:var(--panel)}tr:hover td{background:#16233f}
.empty{color:var(--ok)}footer{color:var(--muted);font-size:12px;padding:0 32px 28px}
</style></head><body>
'@)
    [void]$sb.AppendLine(('<header><h1>{0}</h1><div class="meta">Generated {1} on {2} by {3}</div>' -f (& $enc $Title), (Get-Date -Format 'yyyy-MM-dd HH:mm'), (& $enc ([Environment]::MachineName)), (& $enc ([Environment]::UserName))))
    $paramText = ($Parameter.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, (& $fmt $_.Value) }) -join ' | '
    [void]$sb.AppendLine(('<div class="meta">Parameters: {0}</div></header><main>' -f (& $enc $paramText)))

    [void]$sb.AppendLine('<div class="cards">')
    foreach ($key in $Section.Keys) {
        $count = @($Section[$key]).Count
        $cls = 'card'
        if ($count -gt 0) { $cls = 'card warn' }
        [void]$sb.AppendLine(('<div class="{0}"><div class="n">{1}</div><div class="l">{2}</div></div>' -f $cls, $count, (& $enc $key)))
    }
    [void]$sb.AppendLine('</div>')

    foreach ($key in $Section.Keys) {
        $rows = @($Section[$key])
        [void]$sb.AppendLine(('<section><h2>{0} ({1})</h2>' -f (& $enc $key), $rows.Count))
        if ($rows.Count -eq 0) {
            [void]$sb.AppendLine('<p class="empty">No findings.</p></section>')
            continue
        }
        $columns = @($rows[0].PSObject.Properties | Where-Object { $_.Name -ne 'PSTypeName' } | ForEach-Object { $_.Name })
        [void]$sb.Append('<table><thead><tr>')
        foreach ($c in $columns) { [void]$sb.Append(('<th>{0}</th>' -f (& $enc $c))) }
        [void]$sb.AppendLine('</tr></thead><tbody>')
        foreach ($row in $rows) {
            [void]$sb.Append('<tr>')
            foreach ($c in $columns) { [void]$sb.Append(('<td>{0}</td>' -f (& $enc (& $fmt $row.$c)))) }
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</tbody></table></section>')
    }

    [void]$sb.AppendLine('</main><footer>AD Hygiene Toolkit. Report is read-only output; no directory changes were made while generating it.</footer></body></html>')
    return $sb.ToString()
}
