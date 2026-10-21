# agevault v1.2.0 Windows 中文使用指南

适用于 Windows PowerShell 5.1 和 PowerShell 7。所有下载均来自你的仓库：[v1.2.0 正式版](https://github.com/ly88321/agevault/releases/tag/v1.2.0)。按顺序逐段执行，先用测试文件演练，不要整篇一次运行。

**开始前务必了解：**

- `lock` 成功生成密文后，会擦除并删除原明文目录。重要数据必须另有可靠备份。
- 私钥文件和它的口令都必须保留，缺少任意一项都可能无法恢复。私钥必须放在待加密目录之外。
- 默认 `unlock` 成功后会清理密文。首次验证、共享及故障恢复时，建议使用 `--keep-ciphertext`。
- 下文默认保险库名为 `documents`，各节沿用同一个 PowerShell 窗口中的变量。重开窗口后，需要重新设置 `$AgeVault`、`$Work`、`$AliceKey` 等变量。

## 1. 下载、SHA-256 校验与安装

普通 Intel/AMD 64 位 Windows 选择 `windows-amd64`；Windows ARM64 电脑选择 `windows-arm64`。

macOS 安装包也存在，只是使用操作系统名称 `darwin`：[Intel Mac](https://github.com/ly88321/agevault/releases/download/v1.2.0/agevault-darwin-amd64.tar.gz)、[Apple 芯片 Mac](https://github.com/ly88321/agevault/releases/download/v1.2.0/agevault-darwin-arm64.tar.gz)。本指南的 PowerShell 命令用于 Windows。

下面默认下载 amd64 版本。ARM64 用户只需修改 `$asset`：

```powershell
$ErrorActionPreference = 'Stop'

$asset = 'agevault-windows-amd64.zip'
# Windows ARM64 改为：
# $asset = 'agevault-windows-arm64.zip'

$releaseBase = 'https://github.com/ly88321/agevault/releases/download/v1.2.0'
$installDir = Join-Path $HOME 'Tools\agevault-v1.2.0'
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$zipPath = Join-Path $installDir $asset
$sumsPath = Join-Path $installDir 'SHA256SUMS'
Invoke-WebRequest -UseBasicParsing -Uri "$releaseBase/$asset" -OutFile $zipPath
Invoke-WebRequest -UseBasicParsing -Uri "$releaseBase/SHA256SUMS" -OutFile $sumsPath

$pattern = '^[0-9a-fA-F]{64}\s+\*?' + [regex]::Escape($asset) + '$'
$matchedLines = @(Get-Content -LiteralPath $sumsPath -Encoding UTF8 |
    Where-Object { $_ -match $pattern })
if ($matchedLines.Count -ne 1) {
    throw '校验清单中没有唯一匹配记录，停止安装。'
}

$expectedHash = ($matchedLines[0] -split '\s+')[0]
$actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
if ($actualHash -ine $expectedHash) {
    throw 'SHA-256 不匹配，不要解压或运行该文件。'
}
Write-Host 'SHA-256 校验通过。'

$binDir = Join-Path $installDir 'bin'
Expand-Archive -LiteralPath $zipPath -DestinationPath $binDir -Force
$AgeVault = Join-Path $binDir 'agevault.exe'
$installedVersion = & $AgeVault --version
if ($LASTEXITCODE -ne 0 -or $installedVersion -ne 'v1.2.0') {
    throw '程序版本不符，停止后续操作。'
}
$installedVersion
```

应输出 `v1.2.0`。本次正式版的 Windows ZIP 摘要也可独立核对：

| 安装包 | SHA-256 |
|---|---|
| windows-amd64 | `9c012d5165ca387adf1475cdb1e20ea69a4db288d57dc56fb98624bf77b65de2` |
| windows-arm64 | `f6d300fe01605a402ef48a365c7a617ca3ea41929550ace88459ed4361d3067a` |

SHA-256 校验可以发现下载损坏；仍应确认下载来源是上面的正式发行页。如果把命令保存为 `.ps1`，Windows PowerShell 5.1 建议使用 UTF-8 带 BOM 保存脚本，以正确读取中文。接收者公钥文件则按下文示例使用 UTF-8 无 BOM。

## 2. 后量子密钥生成与首次加解密

建议使用自己账户下的私有、本地 NTFS 工作目录。不要把正在操作的保险库放入公共目录或自动同步目录。

```powershell
$Work = Join-Path $HOME 'AgeVaultWork'
$KeyDir = Join-Path $HOME 'AgeVaultKeys'
New-Item -ItemType Directory -Force -Path $Work, $KeyDir | Out-Null
Set-Location -LiteralPath $Work
$AliceKey = Join-Path $KeyDir 'alice.age'

& $AgeVault documents keygen -pq --key $AliceKey
if ($LASTEXITCODE -ne 0) { throw '密钥生成失败，停止后续操作。' }
```

程序会要求输入并确认私钥口令，输入时不会显示字符。口令不要写进命令、脚本或环境变量。

成功后，口令加密的私钥保存在 `$AliceKey`，公钥接收者写入 `documents\.agevault-recipients`。若 `documents` 不存在，会自动创建。已有同名私钥不会被覆盖。

**先将私钥备份到独立、可靠的介质，口令另行安全保存。不要把私钥放入 `documents`。** `-pq` 生成 X25519 + ML-KEM-768 混合后量子密钥；它不能补救弱口令，也不会自动升级已有密文。不加 `-pq` 则生成传统 X25519 密钥。

先放一个测试文件，再加锁：

```powershell
Set-Content -LiteralPath '.\documents\演示.txt' -Value '这是一次加密测试。' -Encoding UTF8

& $AgeVault documents lock --key $AliceKey
if ($LASTEXITCODE -ne 0) { throw '加锁未完成，请保留现场并检查错误。' }
```

命令会要求私钥口令，验证该密钥的公钥已在接收者列表中。成功后原 `documents` 被擦除，生成 `documents.age`。已有接收者列表时，不带 `--key` 的 `lock` 通常不需要口令；本指南显式指定密钥以验证自己仍是接收者。

解锁并保留密文：

```powershell
& $AgeVault documents unlock --key $AliceKey --keep-ciphertext
if ($LASTEXITCODE -ne 0) { throw '解锁未完成，请保留密文。' }
Get-Content -LiteralPath '.\documents\演示.txt' -Encoding UTF8
```

成功后 `documents` 和 `documents.age` 同时存在。

- 第一个参数只能是当前目录下的单层目录名，如 `documents`；不能填写 `D:\资料\documents`。应先进入它的父目录。
- `--key` 可以使用完整路径。不同保险库或多把私钥时，建议始终显式指定。
- `-pq` 只用于 `keygen`；`--keep-ciphertext` 只用于 `unlock`。

## 3. 保留密文后再次加锁

推荐解锁形式是 `documents unlock --key ... --keep-ciphertext`。如果确实要在成功恢复后清理原密文，可省略保留选项：

```powershell
& $AgeVault documents unlock --key $AliceKey
if ($LASTEXITCODE -ne 0) { throw '解锁或密文清理失败，请检查错误。' }
```

这段命令只能在 `documents` 不存在时执行，不能紧接上一节已成功解锁的示例再运行。

当 `documents.age` 已存在时，`lock` 拒绝覆盖，也不会因此擦除原明文目录。核对恢复的数据后，移走旧密文，再重新加锁：

```powershell
Set-Location -LiteralPath $Work
$BackupDir = Join-Path $HOME 'AgeVaultBackups'
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$archiveBackup = Join-Path $BackupDir ('documents-' + [guid]::NewGuid().ToString('N') + '.age')
Move-Item -LiteralPath '.\documents.age' -Destination $archiveBackup

& $AgeVault documents lock --key $AliceKey
if ($LASTEXITCODE -ne 0) { throw '重新加锁失败，请保留所有副本并检查错误。' }
```

同一块磁盘上的备份目录不能替代独立备份。备份密文可以改名保存，但恢复本例时，应复制回名为 `documents.age` 的文件，并使用 `documents unlock`，以匹配归档内部的目录名。

## 4. 多接收者共享

每个人在自己的电脑上生成并保管私钥，只交换公钥。所有接收者都应使用支持该格式的客户端；同一保险库不能混用传统 X25519 与混合后量子接收者。

### 4.1 Bob 在自己的电脑生成密钥

Bob 先完成第 1 节安装，设置自己的 `$AgeVault`。以下命令在 Bob 的电脑执行：

```powershell
$ErrorActionPreference = 'Stop'
$BobSetup = Join-Path $HOME ('AgeVaultBobSetup-' + [guid]::NewGuid().ToString('N'))
$BobKeyDir = Join-Path $HOME 'AgeVaultKeys'
New-Item -ItemType Directory -Force -Path $BobSetup, $BobKeyDir | Out-Null
Set-Location -LiteralPath $BobSetup
$BobKey = Join-Path $BobKeyDir 'bob.age'

& $AgeVault documents keygen -pq --key $BobKey
if ($LASTEXITCODE -ne 0) { throw 'Bob 密钥生成失败。' }

$publicLines = @(Get-Content -LiteralPath '.\documents\.agevault-recipients' -Encoding UTF8 |
    Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith('#') })
if ($publicLines.Count -ne 1) { throw '预期只有 Bob 的一条公钥，请检查生成目录。' }

$publicFile = Join-Path $BobSetup 'bob-recipient.txt'
[IO.File]::WriteAllText(
    $publicFile,
    $publicLines[0].Trim() + "`n",
    [Text.UTF8Encoding]::new($false)
)
Get-Content -LiteralPath $publicFile -Encoding UTF8
```

Bob 只把 `bob-recipient.txt` 发给 Alice，**不要发送 `bob.age` 或私钥口令**。不要在 Alice 的电脑上代替 Bob 生成并传递私钥。

### 4.2 Alice 添加 Bob 的公钥

以下命令回到 Alice 的原 PowerShell 窗口执行。保险库必须已解锁；若保留着 `documents.age`，先按第 3 节只将旧密文移到备份位置，暂时不要重新加锁。

将收到的 `bob-recipient.txt` 放入 `$Work`。通过可信渠道核对公钥，再追加到列表：

```powershell
Set-Location -LiteralPath $Work
$bobLines = @(Get-Content -LiteralPath '.\bob-recipient.txt' -Encoding UTF8 |
    Where-Object { $_.Trim() -ne '' -and -not $_.TrimStart().StartsWith('#') })
if ($bobLines.Count -ne 1) { throw '接收者文件必须只有一条公钥。' }
$bobRecipient = $bobLines[0].Trim()
$recipientList = (Resolve-Path -LiteralPath '.\documents\.agevault-recipients').Path
[IO.File]::AppendAllText(
    $recipientList,
    "`n" + $bobRecipient + "`n",
    [Text.UTF8Encoding]::new($false)
)
Get-Content -LiteralPath $recipientList -Encoding UTF8
```

使用 UTF-8 无 BOM，避免 Windows PowerShell 默认输出编码造成公钥文件不可读。不要用默认编码的 `Out-File` 重写接收者列表，也不要删除 Alice 的原公钥。

确认列表中的所有公钥来源可信，再加锁：

```powershell
& $AgeVault documents lock --key $AliceKey
if ($LASTEXITCODE -ne 0) { throw '共享加锁失败，请检查接收者列表。' }
```

将新生成的 `documents.age` 发给 Bob。Bob 使用全新接收目录，避免与生成公钥时创建的 `documents` 冲突。以下示例假定收到的文件保存在下载目录，请按实际位置修改 `$SharedCipher`：

```powershell
$SharedCipher = Join-Path $HOME 'Downloads\documents.age'
$BobReceive = Join-Path $HOME ('AgeVaultBobReceive-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $BobReceive | Out-Null
Copy-Item -LiteralPath $SharedCipher -Destination (Join-Path $BobReceive 'documents.age')
Set-Location -LiteralPath $BobReceive

& $AgeVault documents unlock --key $BobKey --keep-ciphertext
if ($LASTEXITCODE -ne 0) { throw 'Bob 解锁失败，请保留密文并检查密钥和口令。' }
```

每人用自己的私钥和口令独立解密。更改接收者列表后，必须重新加锁才会影响新密文；删除公钥不能撤销对方已持有的旧密文副本。

## 5. 故障恢复

发生异常后，停止进一步加锁、清理或覆盖操作，保留现有密文、密钥和残留目录。不要通过重新运行 `keygen` 尝试修复无法解密的旧密文。

### 5.1 在全新目录恢复正式密文副本

适用于加锁或解锁中断，以及原位置已有 `documents` 而提示 `already unlocked` 的情况。选择要恢复的正式密文，不要把 `.agevault-*` 临时文件直接当作完整密文。

```powershell
# 也可改为已备份密文的完整路径，例如 $archiveBackup。
$CipherSource = Join-Path $Work 'documents.age'
$Recovery = Join-Path $HOME ('AgeVaultRecovery-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Recovery | Out-Null
Copy-Item -LiteralPath $CipherSource -Destination (Join-Path $Recovery 'documents.age')
Set-Location -LiteralPath $Recovery

& $AgeVault documents unlock --key $AliceKey --keep-ciphertext
if ($LASTEXITCODE -ne 0) { throw '恢复失败，保留原文件并检查错误。' }
```

确认选择的是所需版本的密文。恢复时保留文件名 `documents.age`，使用 `documents unlock`。先打开、核对重要文件，再处理原位置残留数据。后续回到原工作目录操作前，运行 `Set-Location -LiteralPath $Work`。

若怀疑原磁盘故障，应优先在健康磁盘上保存副本和恢复数据，避免继续向故障盘写入；示例中的 `$Recovery` 也应相应改为健康磁盘上的新目录。

### 5.2 常见错误

| 情况 | 处理方法 |
|---|---|
| 口令错误或密钥不匹配 | 核对 `--key` 和对应口令；新生成的密钥不能恢复旧密文。 |
| 加锁时擦除明文失败 | 原目录可能已部分擦除。保留正式密文和剩余目录，在全新目录使用 `--keep-ciphertext` 恢复验证。 |
| 解锁中途退出或断电 | 保留原密文，在新目录恢复；暂存目录里的文件不能直接当成完整恢复结果。 |
| 提示 `vault restored; could not shred ...` | 明文已恢复，密文却可能已部分擦除。优先检查并备份明文，不要依赖该密文仍完整。 |
| 磁盘空间不足 | 准备足够空间后在新目录恢复；不要删除唯一的密文或密钥来腾空间。 |
| Windows 不支持归档中的文件名 | 保留密文，可在支持这些文件名的 Linux 等 POSIX 环境恢复，不要绕过路径安全检查。 |

查看原工作目录中可能残留的暂存文件：

```powershell
Get-ChildItem -LiteralPath $Work -Force -Filter '.agevault-*'
```

`.agevault-unlock-*` 可能含有明文；其他临时文件也不能自动视作完整备份。未验证恢复结果前，不要批量删除残留。清理失败若报告了具体暂存路径，应在受保护的加密存储环境中检查。

## 6. 兼容性与已知限制

- 新版支持读取历史 ZIP、tar 和旧密钥格式；旧客户端不一定能读取混合后量子密钥或密文。保留旧密文和旧密钥，先在副本上验证恢复。
- 传统保险库不能直接加入后量子公钥；需要后量子保护时，新建后量子保险库并迁移数据，不要照搬旧的接收者列表。
- 新 tar 格式采用流式处理；旧 ZIP 可能需要与归档大小相当的内存。恢复还需要足够磁盘空间。
- 不要并发执行加锁、解锁，也不要在操作过程中编辑、同步或移动保险库内的文件。
- 符号链接、硬链接及特殊文件会被拒绝；原子密文发布需要文件系统支持硬链接，建议使用本地 NTFS。
- Windows 文件权限继承父目录 ACL，程序不能替代正确的账户权限设置。建议配合 BitLocker 等全盘加密。
- SSD、快照、备份和写时复制存储上的覆盖擦除，不能保证历史数据彻底消失。仍需全盘加密及独立备份。
- 断电恢复经过软件模拟测试，不代表对所有 Windows 文件系统、磁盘缓存和硬件故障提供恢复保证。
- 恢复不会保留原时间戳和 Unix 可执行权限。
