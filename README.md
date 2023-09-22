# Normalized Baseline Detection (NBD)
Featured in "Dropping Lotus Bombs: ATT&CK in macOS Purple Team Operations" #OBTSv6
## Method 1 - LOOBin/LOLBin detection using baselines

Many kinds of malware use LOOBins/LOLBins when compromising a host. When attackers use executables that already exist on the host, malicious activity blends in with normal system activity.
### The Problem
Building static detection rules for LOOBins/LOLBins is difficult. If we were to fire an alert every time `touch -t` or `chmod +x`, we would generate way too many false positives. If we try to build exclusion lists to filter out noise, those exclusion lists change too quickly to be maintained.

## Method 2 - Abnormally busy application trees
## Method 3 - Application process trees running unexpected executables
