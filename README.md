# Normalized Baseline Detection (NBD)
Featured in "Dropping Lotus Bombs: ATT&CK in macOS Purple Team Operations" #OBTSv6
## Method 1 - LOOBin/LOLBin detection using baselines

When attackers use executables that already exist on the host like `touch` or `security`, malicious activity blends in with normal system activity. OceanLotus, Bundlore, XCSSET, Shlayer and many other pieces of malware use LOOBins. Some good sources for how LOOBins are used are the [LOOBins Github](https://github.com/infosecB/LOOBins) and [Sentinel One's](https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/) breakdown. 

### The Problem
Building detection rules for LOOBins/LOLBins is difficult. If we were to fire an alert every time we see `touch -t`,`chmod +x`, or `xattr -d com.apple.quarantine` we would generate way too many false positives. If we try to build static exclusion lists to filter out noise, those exclusion lists change too quickly to be maintained.

### A solution

You can profile how LOO/LOLBins are used in your environment, and then only alert on outliers. This approach essentially means generating a _dynamic_ exclusion list that changes as your environment changes. Anomalous events are written to the SIEM for possible alerts. Newly suspicious activity will trigger once and then go quiet, so long as the activity exists in the baseline.

| Baseline period | Sample period |
| ------------- | ------------- |
| 14 days  |  |
|   | 1 hour  |

NBD defines a baseline period (for example, 14 days) and a sample period (for example, 1 hour). Then we find all the uses of a LOOBin (for example, `xattr -d com.apple.quarantine`) over the baseline period and look up the responsible process.

| Command seen during BASELINE  | Responsible process seen during BASELINE |
| ------------- | ------------- |
| `xattr -d -r com.apple.quarantine /Applications/Google Chrome.app`  | `/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateDaemon`  |

If we run the same analysis during our sample period we find the same `xattr` command.

| Command seen during SAMPLE  | Responsible process seen during SAMPLE |
| ------------- | ------------- |
| `xattr -d -r com.apple.quarantine /Applications/Google Chrome.app`  | same as above  |

This exactly matches the entry we saw during the baseline. We won't write an entry to the SIEM, because this is expected behavior from Google Chrome.

#### High-level psuedocode

```
list of commands
`chmod`
`ifconfig`
`kextload`
`kmutil`
`touch`
`security`
`xattr`
...and many more

for each command in list:
    baseline_results = instances of cmd in baseline
    sample_results = instances of cmd in sample period
    for each results in sample_result:
        is this command new? (did we see this command in the baseline?)
        is this responsible process/command pair new? (did we see this pair in the baseline?)
        if yes to either question: write record to SIEM
```

#### Complications

##### Flag restrictions

Some commands are interesting no matter how they're run (`kmutil`, `kextload`). Some commands are only interesting if they're run with specific flags (`xattr`, `chmod`). In our list of commands, we need to specify flag restrictions for the commands like `xattr` and `chmod`. 

Defining the list of commands with flag restrictions
```
cmds_list.append(
    {
        "command": "kmutil",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "xattr",
        "process_arg_restrictions": '(process.args:("com.apple.quarantine" && "-d") OR process.args:("-c"))'
    }
)
```

##### When to ignore arguments entirely
##### Normalization
##### Responsible process anomalies

### The code

#### High-level psuedocode

Define list of commands we care


## Method 2 - Abnormally busy application trees
## Method 3 - Application process trees running unexpected executables
