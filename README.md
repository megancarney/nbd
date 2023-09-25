# Normalized Baseline Detection (NBD)
Featured in "Dropping Lotus Bombs: ATT&CK in macOS Purple Team Operations" #OBTSv6
## Method 1 - LOOBin/LOLBin detection using baselines

When attackers use executables that already exist on the host like `touch` or `security`, malicious activity blends in with normal system activity. OceanLotus, Bundlore, XCSSET, Shlayer and many other pieces of malware use LOOBins. Some good sources for how LOOBins are used are the [LOOBins Github](https://github.com/infosecB/LOOBins) and [Sentinel One's](https://www.sentinelone.com/labs/20-common-tools-techniques-used-by-macos-threat-actors-malware/) breakdown. 

### The Problem
Building detection rules for LOOBins/LOLBins is difficult. If we were to fire an alert every time we see `touch -t`,`chmod +x`, or `xattr -d com.apple.quarantine` we would generate way too many false positives. If we try to build static exclusion lists to filter out noise, those exclusion lists change too quickly to be maintained.

### A solution

You can profile how LOO/LOLBins are used in your environment, and then only alert on outliers. This approach essentially means filtering with a _dynamic_ exclusion list that changes as your environment changes. Anomalous events are written to the SIEM for possible alerts. Newly suspicious activity will trigger once and then go quiet, so long as the activity exists in the baseline.

| Baseline period | Sample period |
| ------------- | ------------- |
| 14 days  |  |
|   | 1 hour  |

NBD defines a baseline period (for example, 14 days) and a non-overlapping sample period (for example, 1 hour). Then we find all the uses of a LOOBin (for example, `xattr -d com.apple.quarantine`) over the baseline period and look up the responsible process.

| Command seen during BASELINE  | Responsible process seen during BASELINE |
| ------------- | ------------- |
| `xattr -d -r com.apple.quarantine /Applications/Google Chrome.app`  | `/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Helpers/GoogleSoftwareUpdateDaemon`  |

If we run the same analysis during our sample period we find the same `xattr` command.

| Command seen during SAMPLE  | Responsible process seen during SAMPLE |
| ------------- | ------------- |
| `xattr -d -r com.apple.quarantine /Applications/Google Chrome.app`  | same as above  |

This exactly matches the responsible process/command pair we saw during the baseline. We won't write an entry to the SIEM, because this is expected behavior from Google Chrome.

Instead of just looking at a command-line and filtering on certain known-good responsible processes, NBD looks at each instance of a LOOBin executing in sample period and asks:
- Has this command been run in my environment recently?
- Has this responsible process run this command in my environment recently?
- How common is this responsible process in our environment?
- What does VirusTotal say about the responsible process?

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
... and many more
```

##### When to ignore arguments entirely

Comparing activity across different machines can get confusing when the command-line arguments vary widely. Let's look at that `xattr` command again as an example.

_Example command_:
`xattr -d -r com.apple.quarantine /Applications/Google Chrome.app`

_How this command would appear on another machine_:
`xattr -d -r com.apple.quarantine /Applications/Google Chrome.app`

For `xattr` the file passed as an argument is likely to be similar on different machines. This means we can safely include arguments when comparing activity between the baseline and the sample period.

For `ifconfig`, the command-line arguments are more confusing.

_Example command_:
`/sbin/ifconfig utun4 inet A.B.C.D A.B.C.D netmask 255.255.0.0 mtu 1500`

_How this command might appear on another machine_:
`/sbin/ifconfig utun6 inet E.F.G.H E.F.G.H netmask 255.255.0.0 mtu 1500`

For `ifconfig`, IP addresses and interface names will vary widely between different machines. We could try to normalize all that away by building specific normalization routines for each command we're monitoring (a possible improvement later?), or we could just ignore ALL command-line arguments in our analysis.

##### Normalization

Command-lines often include directory names that are functionaly similar but don't exactly match. The two most common examples of this are user directories and temporary directories used by installers. As an example:

| Command seen during BASELINE  | Command seen during SAMPLE |
| ------------- | ------------- |
| `xattr -d -r com.apple.quarantine /Users/auser/Applications/Google Chrome.app`  | `xattr -d -r com.apple.quarantine /Users/anotheruser/Applications/Google Chrome.app` |

These two commands are functionally the same, the only difference is the username. We shouldn't label this as anomalous activity.

Here's another example of an temporary directory created by `/usr/sbin/installer` when .pkg files are installed.

| Responsible process | |
| ------------- | ------------- |
| In BASELINE  | `/private/tmp/pkinstallsandbox.53xu2u/scripts/com.adobe.acrobat.acrobatdcupd2300320244.gepy8w/tools/acropatchinstall.app/contents/macos/acropatchinstall` |
| In SAMPLE  | `/private/tmp/pkinstallsandbox.9br8ch/scripts/com.adobe.acrobat.acrobatdcupd2300320215.mmktzv/tools/acropatchinstall.app/contents/macos/acropatchinstall` |

The detailed psuedocode below contains a list of normalizations.

##### Responsible process anomalies

For some processes, data shows the process itself as the responsible process. Some commands are more prone to this anomaly than others. The `system profiler` command often shows up this way. No idea why.

| Command  | Responsible process |
| ------------- | ------------- |
| `/usr/sbin/system_profiler -nospawn -xml SPConfigurationProfileDataType -detailLevel full`  | `/usr/sbin/system_profiler`  |

We can hunt around in the process tree for a better answer. There are a few ways to do this.

Look for an executable in the thread that _isn't_ a built-in executable. This means looking through the process tree for a process that doesn't start with `/usr/` or `/bin/*` or `/sbin/*`. Our search on the SIEM looks something like this.
```
event.name:"process"
exec_chain.thread_uuid:("<thread_uuid>")
host.hostname:("<hostname>")
subject.process.name:"/*"
NOT (subject.process.name:("/usr/*" || "/bin/*" || "/sbin/*"))
GROUPBY TERM subject.process.name
```

Look for a responsible process in the thread that _isn't_ a built-in executable. Same query as above, but instead we're looking at the responsible process field. Our search on the SIEM looks something like this.
```
event.name:"process"
exec_chain.thread_uuid:("<thread_uuid>")
host.hostname:("<hostname>")
subject.responsible_process_name:"/*"
NOT (subject.responsible_process_name:("/usr/*" || "/bin/*" || "/sbin/*"))
GROUPBY TERM subject.responsible_process_name
```

Look for an open command similar to `open /Applications/Google Chrome.app` or a shell command similar to `/bin/sh ashellscript.sh`. Our search on the SIEM would be something like this.
```
event.name:"process"
exec_chain.thread_uuid:("<thread_uuid>")
host.hostname:("<hostname>")
subject.responsible_process_name:"/usr/bin/open" ||
process.command_line:/\/bin\/[a-z]{0,5}sh .*/
GROUPBY TERM process.command_line
```


### The code

#### High-level psuedocode

Define list of commands we care


## Method 2 - Abnormally busy application trees
## Method 3 - Application process trees running unexpected executables
