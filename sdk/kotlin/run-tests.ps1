# Compiles sdk/kotlin's main + test sources with kotlinc and runs the test suite.
#
# No Gradle in this build (plain kotlinc CLI, confirmed explicitly rather than bootstrapping
# a second build tool this session) -- set $env:KOTLINC to the kotlinc.bat path if it isn't
# already on PATH, and $env:JAVA_HOME to a JDK 17+ install.
param(
    [string]$Kotlinc = $env:KOTLINC,
    [string]$JavaHome = $env:JAVA_HOME
)

if (-not $Kotlinc) { $Kotlinc = "kotlinc" }
if ($JavaHome) { $env:JAVA_HOME = $JavaHome }

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
& $Kotlinc src\main\kotlin src\test\kotlin -include-runtime -d build\test.jar
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$javaExe = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME "bin\java.exe" } else { "java" }
& $javaExe -cp build\test.jar dev.ubc.RunTestsKt
exit $LASTEXITCODE
