# AdHygieneToolkit module loader.
# The ActiveDirectory (RSAT) module is an external dependency. It is checked at call time,
# not import time, so the module can be imported (and unit tested) on machines without RSAT.

$script:AdhLogPath = $null

$private = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Private') -Filter '*.ps1' -ErrorAction SilentlyContinue)
$public = @(Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($private + $public)) {
    . $file.FullName
}

Export-ModuleMember -Function $public.BaseName
