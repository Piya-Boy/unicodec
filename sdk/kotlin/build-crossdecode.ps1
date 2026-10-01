# Compiles sdk/kotlin's main + test + tools sources into a single runnable jar for the
# CrossDecode CLI. Separate from run-tests.ps1 since the CLI needs the tools/ sources too.
param(
    [string]$Kotlinc = $env:KOTLINC,
    [string]$JavaHome = $env:JAVA_HOME
)

if (-not $Kotlinc) { $Kotlinc = "kotlinc" }
if ($JavaHome) { $env:JAVA_HOME = $JavaHome }

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

& $Kotlinc src\main\kotlin src\test\kotlin src\tools\kotlin -include-runtime -d build\crossdecode.jar
exit $LASTEXITCODE
