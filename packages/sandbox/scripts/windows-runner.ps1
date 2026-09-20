# ============================================================================
# RTQ Windows OS-level sandbox runner (AppContainer + Job Object).
#
# SECURITY INVARIANTS
# -------------------
# 1. The target process is created SUSPENDED inside a Job Object created by
#    this helper BEFORE its first instruction runs.
# 2. Job handles stay open for the target's lifetime and
#    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE guarantees the whole process tree is
#    terminated if this helper exits.
# 3. The target runs as an APP CONTAINER (Windows 8+): SECURITY_CAPABILITIES
#    proc-thread attribute via CreateProcessW with ZERO capabilities => no
#    network. Read/write is restricted to paths whose ACLs grant the package
#    SID (allowlisted directories + workspace + target executable), granted
#    via icacls before launch.
# 4. Every setup failure returns a structured error and exits non-zero; the
#    target is NEVER run uncontained. No unsandboxed fallback.
# 5. Grants and the AppContainer profile are removed after the run.
# ============================================================================

param([Parameter(Mandatory=$true)][string]$PayloadPath)

$ErrorActionPreference = 'Stop'
$ResultMarker = 'RTQ_SANDBOX_RESULT:'

$payload = Get-Content -LiteralPath $PayloadPath -Raw -Encoding UTF8 | ConvertFrom-Json

function Emit-Result([hashtable]$Result) {
    $json = $Result | ConvertTo-Json -Compress -Depth 10
    Write-Output "${ResultMarker}$json"
}

function Fail-Sandbox([string]$Code, [string]$Message) {
    $err = @{
        sandboxed = $false
        code = $Code
        error = $Message
    }
    Emit-Result $err
    exit 1
}

# ---------------------------------------------------------------------------
# P/Invoke definitions
# ---------------------------------------------------------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class RTQNative {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetInformationJobObject(IntPtr hJob, int JobObjectInformationClass, IntPtr lpJobObjectInformation, uint cbJobObjectInformationLength);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool IsProcessInJob(IntPtr hProcess, IntPtr hJob, out bool result);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref RTQSTARTUPINFOEX lpStartupInfo, out RTQPROCESS_INFORMATION lpProcessInformation);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int CreateAppContainerProfile(string pszAppContainerName, string pszDisplayName, string pszDescription, IntPtr pCapabilities, uint dwCapabilityCount, out IntPtr pSid);
    [DllImport("userenv.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int DeriveAppContainerSidFromAppContainerName(string pszAppContainerName, out IntPtr pSid);
    [DllImport("userenv.dll", SetLastError=true)]
    public static extern bool DeleteAppContainerProfile(string pszAppContainerName);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ConvertSidToStringSidW(IntPtr pSid, out IntPtr pStringSid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
}

[StructLayout(LayoutKind.Sequential)]
public struct RTQJOBOBJECT_BASIC_LIMIT_INFORMATION {
    public long PerProcessUserTimeLimit;
    public long PerJobUserTimeLimit;
    public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize;
    public UIntPtr MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public UIntPtr Affinity;
    public uint PriorityClass;
    public uint SchedulingClass;
}

[StructLayout(LayoutKind.Sequential)]
public struct RTQIO_COUNTERS {
    public ulong ReadOperationCount;
    public ulong WriteOperationCount;
    public ulong OtherOperationCount;
    public ulong ReadTransferCount;
    public ulong WriteTransferCount;
    public ulong OtherTransferCount;
}

[StructLayout(LayoutKind.Sequential)]
public struct RTQJOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    public RTQJOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    public RTQIO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit;
    public UIntPtr JobMemoryLimit;
    public UIntPtr PeakProcessMemoryUsed;
    public UIntPtr PeakJobMemoryUsed;
}

[StructLayout(LayoutKind.Sequential)]
public struct RTQSTARTUPINFO {
    public uint cb;
    public IntPtr lpReserved;
    public IntPtr lpDesktop;
    public IntPtr lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public ushort wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct RTQSTARTUPINFOEX {
    public RTQSTARTUPINFO StartupInfo;
    public IntPtr lpAttributeList;
}

[StructLayout(LayoutKind.Sequential)]
public struct RTQPROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
public struct RTQSECURITY_CAPABILITIES {
    public IntPtr AppContainerSid;
    public IntPtr Capabilities;
    public uint CapabilityCount;
    public uint Reserved;
}
"@

# ---------------------------------------------------------------------------
# Job Object
# ---------------------------------------------------------------------------
$jobHandle = [RTQNative]::CreateJobObjectW([IntPtr]::Zero, $null)
if ($jobHandle -eq [IntPtr]::Zero) { Fail-Sandbox 'SANDBOX_SETUP_FAILED' 'CreateJobObjectW failed' }

$jobLimit = New-Object RTQJOBOBJECT_EXTENDED_LIMIT_INFORMATION
$jobLimit.BasicLimitInformation.LimitFlags =
    0x00000008 -bor 0x00002000  # KILL_ON_JOB_CLOSE | ACTIVE_PROCESS
$jobLimit.BasicLimitInformation.ActiveProcessLimit = [uint32]$payload.sandbox.maxProcesses
if ($payload.sandbox.maxMemoryBytes -gt 0) {
    $jobLimit.BasicLimitInformation.LimitFlags = $jobLimit.BasicLimitInformation.LimitFlags -bor 0x00000200
    $jobLimit.JobMemoryLimit = [UIntPtr][uint64]$payload.sandbox.maxMemoryBytes
}
$size = [System.Runtime.InteropServices.Marshal]::SizeOf([RTQJOBOBJECT_EXTENDED_LIMIT_INFORMATION])
$jobLimitPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[System.Runtime.InteropServices.Marshal]::StructureToPtr($jobLimit, $jobLimitPtr, $false)
$ok = [RTQNative]::SetInformationJobObject($jobHandle, 9, $jobLimitPtr, [uint32]$size)  # JobObjectExtendedLimitInformation
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($jobLimitPtr)
if (-not $ok) { Fail-Sandbox 'SANDBOX_SETUP_FAILED' 'SetInformationJobObject failed' }

# ---------------------------------------------------------------------------
# AppContainer profile + SID
# ---------------------------------------------------------------------------
$suffix = [guid]::NewGuid().ToString('N').Substring(0,8)
$acName = 'rtq-ac-' + $suffix
$acSidPtr = [IntPtr]::Zero

$acResult = [RTQNative]::CreateAppContainerProfile($acName, 'RTQ Sandbox', 'RTQ AppContainer sandbox', [IntPtr]::Zero, 0, [ref]$acSidPtr)
if ($acResult -ne 0) {
    $acResult2 = [RTQNative]::DeriveAppContainerSidFromAppContainerName($acName, [ref]$acSidPtr)
    if ($acResult2 -ne 0) { Fail-Sandbox 'SANDBOX_SETUP_FAILED' "AppContainer profile creation failed ($acResult / $acResult2)" }
}
if ($acSidPtr -eq [IntPtr]::Zero) { Fail-Sandbox 'SANDBOX_SETUP_FAILED' 'AppContainer SID derivation returned null' }

$sidStringPtr = [IntPtr]::Zero
if (-not [RTQNative]::ConvertSidToStringSidW($acSidPtr, [ref]$sidStringPtr)) {
    Fail-Sandbox 'SANDBOX_SETUP_FAILED' 'ConvertSidToStringSidW failed'
}
$acSidString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($sidStringPtr)

# ---------------------------------------------------------------------------
# Resolve the executable
# ---------------------------------------------------------------------------
$executable = $null
try { $executable = (Get-Command -Name $payload.command -ErrorAction SilentlyContinue).Source } catch { }
if (-not $executable) {
    foreach ($candidate in @($payload.command, (Join-Path $payload.sandbox.workspace $payload.command))) {
        if (Test-Path -LiteralPath $candidate) { $executable = (Resolve-Path -LiteralPath $candidate).Path; break }
    }
}
if (-not $executable) { Fail-Sandbox 'SANDBOX_SETUP_FAILED' "Could not resolve executable: $($payload.command)" }

# ---------------------------------------------------------------------------
# OS-enforced directory allowlist via icacls grants on the package SID
# ---------------------------------------------------------------------------
$writeDirs = @($payload.sandbox.writeDirs) + @($payload.sandbox.workspace)
$readDirs = @($payload.sandbox.readDirs)

$exeDir = Split-Path -Parent $executable
if ($exeDir -and (Test-Path -LiteralPath $exeDir)) {
    & icacls $exeDir /grant ('*S-1-15-2-1:RX') 2>$null | Out-Null
}
foreach ($dir in $readDirs) {
    if (Test-Path -LiteralPath $dir) {
        & icacls $dir /grant ('*' + $acSidString + ':(OI)(CI)RX') 2>$null | Out-Null
    }
}
foreach ($dir in $writeDirs) {
    if (Test-Path -LiteralPath $dir) {
        & icacls $dir /grant ('*' + $acSidString + ':(OI)(CI)M') 2>$null | Out-Null
    }
}

# ---------------------------------------------------------------------------
# Command line + environment
# ---------------------------------------------------------------------------
$commandLine = '"' + $executable + '"'
foreach ($a in @($payload.args)) {
    $commandLine += ' "' + ([string]$a).Replace('"','\"') + '"'
}

$envMap = @{}
foreach ($prop in $payload.env.PSObject.Properties) { $envMap[$prop.Name] = [string]$prop.Value }
$envBlock = $null
if ($envMap.Count -gt 0) {
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($key in $envMap.Keys) { $lines.Add("$key=$($envMap[$key])") }
    $envBlock = [System.Text.Encoding]::Unicode.GetBytes(($lines -join "`0") + "`0`0")
}

# ---------------------------------------------------------------------------
# SECURITY_CAPABILITIES + suspended process + job assignment
# ---------------------------------------------------------------------------
$secCap = New-Object RTQSECURITY_CAPABILITIES
$secCap.AppContainerSid = $acSidPtr
$secCap.Capabilities = [IntPtr]::Zero
$secCap.CapabilityCount = 0
$secCap.Reserved = 0

$attribSize = [IntPtr]::Zero
[RTQNative]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$attribSize) | Out-Null
$attribList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($attribSize)
$initOk = [RTQNative]::InitializeProcThreadAttributeList($attribList, 1, 0, [ref]$attribSize)
if (-not $initOk) { Fail-Sandbox 'SANDBOX_SETUP_FAILED' 'InitializeProcThreadAttributeList failed' }

$secCapSize = [System.Runtime.InteropServices.Marshal]::SizeOf([RTQSECURITY_CAPABILITIES])
$secCapPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($secCapSize)
[System.Runtime.InteropServices.Marshal]::StructureToPtr($secCap, $secCapPtr, $false)

# PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 9
$updateOk = [RTQNative]::UpdateProcThreadAttribute($attribList, 0, [IntPtr]9, $secCapPtr, [IntPtr]$secCapSize, [IntPtr]::Zero, [IntPtr]::Zero)
if (-not $updateOk) { Fail-Sandbox 'SANDBOX_SETUP_FAILED' 'UpdateProcThreadAttribute (SECURITY_CAPABILITIES) failed' }

$si = New-Object RTQSTARTUPINFOEX
$si.StartupInfo.cb = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf([RTQSTARTUPINFOEX])
$siExSize = [System.Runtime.InteropServices.Marshal]::SizeOf([RTQSTARTUPINFOEX])
$siExPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($siExSize)
[System.Runtime.InteropServices.Marshal]::StructureToPtr($si, $siExPtr, $false)
$attrPtrOffset = [System.Runtime.InteropServices.Marshal]::SizeOf([RTQSTARTUPINFO])
$attrPtrBytes = [BitConverter]::GetBytes($attribList.ToInt64())
[System.Runtime.InteropServices.Marshal]::Copy($attrPtrBytes, 0, [IntPtr]::Add($siExPtr, $attrPtrOffset), $attrPtrBytes.Length)

$creationFlags = 0x08000000 -bor 0x00000004  # EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED
$pi = New-Object RTQPROCESS_INFORMATION

$createOk = [RTQNative]::CreateProcessW($null, $commandLine, [IntPtr]::Zero, [IntPtr]::Zero, $false, $creationFlags, $envBlock, $payload.sandbox.workspace, [ref]$siExPtr, [ref]$pi)
if (-not $createOk) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Fail-Sandbox 'SANDBOX_SETUP_FAILED' "CreateProcessW failed (Win32 error $err)"
}

# Job assignment BEFORE any instruction runs (process is suspended).
$assignOk = [RTQNative]::AssignProcessToJobObject($jobHandle, $pi.hProcess)
if (-not $assignOk) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    [RTQNative]::TerminateProcess($pi.hProcess, 1) | Out-Null
    Fail-Sandbox 'SANDBOX_SETUP_FAILED' "AssignProcessToJobObject failed (Win32 error $err)"
}
$isInJob = $false
$verifyOk = [RTQNative]::IsProcessInJob($pi.hProcess, $jobHandle, [ref]$isInJob)
if (-not $verifyOk -or -not $isInJob) {
    [RTQNative]::TerminateProcess($pi.hProcess, 1) | Out-Null
    Fail-Sandbox 'SANDBOX_SETUP_FAILED' 'Job assignment verification failed'
}

# ---------------------------------------------------------------------------
# Resume, wait, collect exit code
# ---------------------------------------------------------------------------
[RTQNative]::ResumeThread($pi.hThread) | Out-Null

$waited = [RTQNative]::WaitForSingleObject($pi.hProcess, [uint32]$payload.timeoutMs)
$timedOut = ($waited -ne 0)  # WAIT_OBJECT_0 = 0
$exitCode = 0
if (-not $timedOut) {
    [RTQNative]::GetExitCodeProcess($pi.hProcess, [ref]$exitCode) | Out-Null
} else {
    # Closing the job handle kills the whole tree (KILL_ON_JOB_CLOSE).
    [RTQNative]::CloseHandle($jobHandle)
    $jobHandle = [IntPtr]::Zero
    [RTQNative]::CloseHandle($pi.hProcess) | Out-Null
    $pi.hProcess = [IntPtr]::Zero
    $exitCode = 124
}

# ---------------------------------------------------------------------------
# Cleanup (best effort)
# ---------------------------------------------------------------------------
foreach ($dir in $readDirs) {
    if (Test-Path -LiteralPath $dir) { & icacls $dir /remove ('*' + $acSidString) 2>$null | Out-Null }
}
foreach ($dir in $writeDirs) {
    if (Test-Path -LiteralPath $dir) { & icacls $dir /remove ('*' + $acSidString) 2>$null | Out-Null }
}
if ($exeDir -and (Test-Path -LiteralPath $exeDir)) {
    & icacls $exeDir /remove '*S-1-15-2-1' 2>$null | Out-Null
}
[RTQNative]::DeleteAppContainerProfile($acName) | Out-Null
if ($attribList -ne [IntPtr]::Zero) { [RTQNative]::DeleteProcThreadAttributeList($attribList) | Out-Null }
if ($pi.hThread -ne [IntPtr]::Zero) { [RTQNative]::CloseHandle($pi.hThread) | Out-Null }
if ($pi.hProcess -ne [IntPtr]::Zero) { [RTQNative]::CloseHandle($pi.hProcess) | Out-Null }
if ($jobHandle -ne [IntPtr]::Zero) { [RTQNative]::CloseHandle($jobHandle) | Out-Null }

$result = @{
    sandboxed = $true
    exitCode = $exitCode
    jobAssigned = $true
    appContainer = $true
    restrictedToken = $false
    integrityLevel = 'appcontainer'
    timedOut = $timedOut
}
Emit-Result $result
exit 0