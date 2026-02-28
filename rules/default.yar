// ScanRook default YARA rules — bundled with the scanner binary.
// Applied automatically during --mode deep scans.

rule CryptoMiner_XMRig {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        severity = "HIGH"
        category = "crypto_miner"
    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "stratum+tcp://" ascii
        $s3 = "stratum+ssl://" ascii
        $s4 = "mining.subscribe" ascii
        $s5 = "mining.authorize" ascii
        $pool1 = "pool.minexmr.com" ascii
        $pool2 = "xmr.pool.minergate.com" ascii
        $pool3 = "monerohash.com" ascii
    condition:
        ($s1 and ($s2 or $s3)) or ($s4 and $s5) or any of ($pool*)
}

rule CryptoMiner_Generic {
    meta:
        description = "Detects generic cryptocurrency mining indicators"
        severity = "HIGH"
        category = "crypto_miner"
    strings:
        $s1 = "cryptonight" ascii nocase
        $s2 = "hashrate" ascii nocase
        $s3 = "mining" ascii nocase
        $s4 = "stratum" ascii nocase
        $wallet = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
    condition:
        3 of ($s*) or ($wallet and 2 of ($s*))
}

rule WebShell_PHP {
    meta:
        description = "Detects common PHP web shell patterns"
        severity = "CRITICAL"
        category = "webshell"
    strings:
        $e1 = "eval($_POST" ascii
        $e2 = "eval($_GET" ascii
        $e3 = "eval($_REQUEST" ascii
        $e4 = "eval(base64_decode(" ascii
        $e5 = "assert($_POST" ascii
        $e6 = "assert($_GET" ascii
        $e7 = "system($_GET" ascii
        $e8 = "passthru($_GET" ascii
        $e9 = "shell_exec($_GET" ascii
        $c2 = "c99shell" ascii nocase
        $c3 = "r57shell" ascii nocase
        $c4 = "WSO " ascii
        $c5 = "FilesMan" ascii
    condition:
        any of ($e*) or any of ($c*)
}

rule WebShell_JSP {
    meta:
        description = "Detects JSP web shell patterns"
        severity = "CRITICAL"
        category = "webshell"
    strings:
        $s1 = "Runtime.getRuntime().exec" ascii
        $s2 = "request.getParameter" ascii
        $s3 = "ProcessBuilder" ascii
        $cmd = /Runtime\.getRuntime\(\)\.exec\(request\.getParameter/ ascii
    condition:
        ($s1 and $s2) or $cmd
}

rule ReverseShell_Bash {
    meta:
        description = "Detects bash reverse shell patterns"
        severity = "CRITICAL"
        category = "reverse_shell"
    strings:
        $s1 = "/dev/tcp/" ascii
        $s2 = "bash -i" ascii
        $s3 = ">&/dev/tcp/" ascii
        $s4 = "0>&1" ascii
        $s5 = "mkfifo /tmp/" ascii
        $nc1 = /nc\s+-[elp]+\s/ ascii
        $nc2 = /ncat\s+-[elp]+\s/ ascii
    condition:
        ($s1 and ($s2 or $s4)) or $s3 or ($s5 and ($nc1 or $nc2))
}

rule ReverseShell_Python {
    meta:
        description = "Detects Python reverse shell patterns"
        severity = "CRITICAL"
        category = "reverse_shell"
    strings:
        $s1 = "socket.socket" ascii
        $s2 = "subprocess.call" ascii
        $s3 = "os.dup2" ascii
        $s4 = "/bin/sh" ascii
        $s5 = "connect((" ascii
    condition:
        ($s1 and $s5 and ($s2 or $s3) and $s4)
}

rule LeakedSecrets_AWS {
    meta:
        description = "Detects potential AWS access key IDs"
        severity = "HIGH"
        category = "leaked_secret"
    strings:
        $ak = /AKIA[0-9A-Z]{16}/ ascii
        $sk = /[0-9a-zA-Z\/+]{40}/ ascii
        $label1 = "aws_access_key_id" ascii nocase
        $label2 = "aws_secret_access_key" ascii nocase
    condition:
        $ak or ($label1 and $label2 and $sk)
}

rule LeakedSecrets_PrivateKey {
    meta:
        description = "Detects embedded private keys"
        severity = "HIGH"
        category = "leaked_secret"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $generic = "-----BEGIN PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule LeakedSecrets_GenericToken {
    meta:
        description = "Detects hardcoded API tokens and passwords"
        severity = "MEDIUM"
        category = "leaked_secret"
    strings:
        $gh = /ghp_[0-9a-zA-Z]{36}/ ascii
        $gho = /gho_[0-9a-zA-Z]{36}/ ascii
        $slack = /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/ ascii
        $stripe = /sk_live_[0-9a-zA-Z]{24,}/ ascii
    condition:
        any of them
}

rule SuspiciousBinary_UPX {
    meta:
        description = "Detects UPX-packed binaries (often used for malware obfuscation)"
        severity = "MEDIUM"
        category = "suspicious_binary"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
    condition:
        uint32(0) == 0x464C457F and ($upx1 or $upx2 or $upx3)
}

rule SuspiciousBinary_AntiDebug {
    meta:
        description = "Detects anti-debugging techniques in ELF binaries"
        severity = "MEDIUM"
        category = "suspicious_binary"
    strings:
        $ptrace = "ptrace" ascii
        $proc_status = "/proc/self/status" ascii
        $tracer = "TracerPid" ascii
    condition:
        uint32(0) == 0x464C457F and ($ptrace and ($proc_status or $tracer))
}

rule Backdoor_SSHKey_Injection {
    meta:
        description = "Detects SSH authorized_keys injection patterns"
        severity = "HIGH"
        category = "backdoor"
    strings:
        $auth = ".ssh/authorized_keys" ascii
        $append = ">>" ascii
        $key = "ssh-rsa " ascii
    condition:
        $auth and $append and $key
}
