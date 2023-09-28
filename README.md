# Normalized Baseline Detection (NBD)
Featured in "Dropping Lotus Bombs: ATT&CK in macOS Purple Team Operations" #OBTSv6

## How does NBD detect OceanLotus activity?

The examples below are for Method 1 - LOOBin/LOLBin detection using baselines.

NBD is essentially a filtering and enrichment pipeline. We filter out what we know to be normal. Then we take possibly suspicious command executions and enrich them with context:
- How common is this command in our environment?
- How common is this responsible process in our environment?
- What does VirusTotal say about the responsible process?

### IOC: Use of touch to backdate files

OceanLotus uses the `touch -t` command to backdate files. Unfortunately, we can't alert everytime we see `touch` run with the `-t` flag. There's too much background activity.

Endpoint Security Framework (ESF) records for OceanLotus `touch -t`
```
# Responsible process
{
  "event":"ES_EVENT_TYPE_NOTIFY_EXEC",
  "process": {
    "team_id":"",
    "ruid":501,
    "uid":501,
    "euid":501,
    "tty":"None",
    "ppid":1,
    "path":"/bin/bash",
    "responsible_pid":5718,
    "username":"loonicorn",
    "command":" /bin/bash /private/tmp/conkylan.app/Contents/MacOS/conkylan",
    "pid":5718,
    "original_ppid":1,
    "pgid":5718,
    "session_id":1
  }
  "timestamp":"2023-09-14 12:17:42"
}

# Command
{
  "event":"ES_EVENT_TYPE_NOTIFY_EXEC",
  "process": {
    "team_id":"",
    "ruid":501,
    "uid":501,
    "euid":501,
    "tty":"None",
    "ppid":5718,
    "path":"/usr/bin/touch",
    "responsible_pid":5718,
    "username":"loonicorn",
    "command":" touch -t 1910071234 /Users/loonicorn/Library/LaunchAgents/com.apple.launchpad.plist",
    "pid":5758,
    "original_ppid":5718,
    "pgid":5718,
    "session_id":1
    },
  "timestamp":"2023-09-14 12:17:43"
}
```

#### Compare to baseline

This exact `touch` command isn't in the baseline for normal activity. NBD identifies the command as anomalous and writes a record like this to the SIEM.

```
{
  "process": {
    "normalized_command_line": "touch -t 1910071234 /*/Library/LaunchAgents/com.apple.launchpad.plist",
    "responsible": {
      "name": "bash",
      "pid": 5718,
      "executable": "/bin/bash",
      "hash": {
        "sha1": "c2995561f3026a09ce262abdac8775499b01ac36"
      }
    },
    "name": "touch",
    "pid": 5758,
    "command_line": "touch -t 1910071234 /Users/loonicorn/Library/LaunchAgents/com.apple.launchpad.plist"
  },
  "rule": {
    "meta": {
      "reason_for_alert": "not seen in baseline",
      "arg_restrictions": "process.args:(\"-t\")"
    },
    "name": "rare recon command",
  },
  "stats": {
    "processes_seen_in_baseline": 0,
    "processes_seen_in_sample": 1,
    "other_machines_with_responsible_file": 7787,
    "other_machines_with_responsible_hash": 3923
  },
  "host": {
    "hostname": "loonicorn",
    "os": {
      "type": "macos"
    }
  },
  "virustotal": {
    "malicious": 0,
    "signature_info": {
      "signers": "Apple Inc.; Apple Inc.; Apple Inc.",
      "verified": "Valid"
    },
    "tags": "checks-hostname,multi-arch,64bits,macho,known-distributor,arm,legit,signed"
  },
}
```

#### Build an alert

Here's what a simple rule might look like in your SIEM:
```
INDEX enriched_commands
process.name:”touch"
```

Despite everything NBD filters out, you might need to do some filtering.
```
# Filter out a specific process causing false positives
INDEX enriched_commands
process.name:”touch"
NOT process.responsible.executable:"REDACTED"
```

### IOC: Use of chmod to add the executable bit

Endpoint Security Framework (ESF) records for OceanLotus `chmod +x`
```
# Responsible process
{
  "event":"ES_EVENT_TYPE_NOTIFY_EXEC",
  "process":{
    "team_id":"",
    "ruid":501,
    "uid":501,
    "euid":501,
    "tty":"None",
    "ppid":5760,
    "path":"/Users/loonicorn/Library/WebKit/com.apple.launchpad",
    "responsible_pid":5765,
    "username":"loonicorn",
    "command":" /Users/loonicorn/Library/WebKit/com.apple.launchpad",
    "pid":5765,
    "original_ppid":5760,
    "pgid":5718,
    "session_id":1
  },
  "timestamp":"2023-09-14 12:17:43"
}

# Command process
{
  "event":"ES_EVENT_TYPE_NOTIFY_EXEC",
  "process":{
    "team_id":"",
    "ruid":501,
    "uid":501,
    "euid":501,
    "tty":"None",
    "ppid":5765,
    "path":"/bin/chmod",
    "responsible_pid":5765,
    "username":"loonicorn",
    "command":" chmod +x /Users/loonicorn/Library/WebKit/osx.download",
    "pid":7915,
    "original_ppid":5765,
    "pgid":5718,
    "session_id":1
  },
  "timestamp":"2023-09-14 12:24:42"
}
```

#### Compare to baseline

NBD would identify this command as anomalous because this exact command doesn't exist in the baseline. The record in the SIEM would be similar to below. We're assuming that this variant of OceanLotus (`/Users/loonicorn/Library/WebKit/com.apple.launchpad`) is unknown to VT and unsigned.

```
{
  "process": {
    "normalized_command_line": "chmod +x /*/Library/WebKit/osx.download",
    "responsible": {
      "code_signature": {},
      "name": "com.apple.launchpad",
      "executable": "/Users/loonicorn/Library/WebKit/com.apple.launchpad"
      "pid": 5765,
      "hash": {
        "sha1": "redacted"
      },
    },
    "name": "chmod",
    "pid": 7915,
    "command_line": "chmod +x /Users/loonicorn/Library/WebKit/osx.download"
  },
  "rule": {
    "meta": { 
      "reason_for_alert": "not seen in the baseline period",
      "arg_restrictions": "process.args:(\"+x\" || \"777\")",
    },
  "name": "rare recon command",
  "stats": {
    "processes_seen_in_baseline": 0,
    "processes_seen_in_sample": 3,
    "other_machines_with_responsible_file": 0,
    "other_machines_with_responsible_hash": 0
  },
  "host": {
    "hostname": "loonicorn",
    "os": {
      "type": "macos"
    }
  },
  "virustotal": {
    "message": "Request error: 404 Client Error: Not Found for ",
    "signature_info": {}
  }
}
```

#### Build an alert

Unfortunately, there is a lot of background activity for `chmod +x`. You will probably need to filter more aggresively than we did in the previous example.

Some options - you will need to mix and match according to your environment.
```
# Only alert when the command is completely new
INDEX enriched_commands
process.name:"chmod"
rule.meta.reason_for_alert:"not seen in the baseline period"

# Only alert when the command is completely new
# excluding background activity not filtered by NBD
INDEX enriched_commands
process.name:"chmod"
rule.meta.reason_for_alert:"not seen in the baseline period"
NOT process.command_line:(
  "redacted1"
  || "redacted2"
)

# Only alert when the responsible file/hash are rare
INDEX enriched_commands
process.name:"chmod"
(stats.other_machines_with_responsible_file:<10 ||
 stats.other_machines_with_responsible_file:<10)


# Only alert when the responsible file/hash are unique
# and the command is completely new
INDEX enriched_commands
process.name:"chmod"
rule.meta.reason_for_alert:"not seen in the baseline period"
(
  stats.other_machines_with_responsible_file:0
  && stats.other_machines_with_responsible_hash:0
)

# Only alert when VT doesn't know the responsible process hash
# or knows the responsible hash is malicious
INDEX enriched_commands
process.name:"chmod"
(
  virustotal.message:*404*
  || virustotal.malicious:>0
)
```

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
... full list is in psuedocode section below
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

These two commands are functionally the same, the only difference is the username. We shouldn't treat this as new activity.

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

We can hunt around in the process tree for a better answer. There are a few ways to do this. I've include sample searches in the psuedocode section below.

**Look for an executable in the thread that _isn't_ a built-in executable.** This means looking through the process tree for a process that doesn't start with `/usr/` or `/bin/*` or `/sbin/*`.

**Look for a responsible process in the thread that _isn't_ a built-in executable.** Same query as above, but instead we're looking at the responsible process field.

**Look for an open command or a shell command running a shell script.** These are commands like `open /Applications/Google Chrome.app` or `/bin/sh ashellscript.sh`.

### The psuedocode

I would love to release a tool that you can just plug into your own SIEM, but that would be a very big project. Each SIEM has its own query language. And the field names for the data in your SIEM vary based on what tools you're using to collect process data and how many of those fields you've converted to ECS. Instead, I'm going to release psuedcode you should be able to adapt to your environment.

#### More detailed but still high-level psuedocode

```
for each command:
    baseline = normalize(instances of cmd in baseline (maybe with flag restrictions))
    sample = normalize(instances of cmd in sample (maybe with flag restrictions))

    for each result in sample:
       seen in the baseline?
       seen with the same responsible process in the baseline?*
       if no to either question: enrich with context and write record to SIEM

    for each result in sample:
      seen in the baseline ignoring arguments?
      seen with the same resp. process in the baseline ignoring arguments?*
      if no to either question: enrich with context and write record to SIEM

* if responsible process == self, look in process tree for a better answer
```

Normalizations (you will probably need to add some of your own to this list)
```
Responsible processes:
User directories
re.sub("\/users\/<yourusernameregex>\/", "/*/", responsible_process)

AppTranslocation
re.sub(“\/private\/var\/folders\/[a-z0-9_]{2}\/[a-z0-9_]{30}\/[a-z]{1}\/apptranslocation\/[a-z0-9\-]{36}\/[a-z]{1}\/","/*/",new_responsible_process)

Temp dirs created by installer
re.sub(“\/private\/tmp\/pkinstallsandbox\.[a-z0-9]{6}\/","/*/",new_responsible_process)
re.sub(“\/var\/folders\/[a-z0-9_]{2}\/[a-z0-9_]{30}\/[a-z]{1}\/“,”/*/",new_responsible_process)

System extension activity
re.sub("\/library\/systemextensions\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\/","/library/systemextensions/*/",new_responsible_process)

Command-lines:
User directories
re.sub("\/users\/<yourusernameregex>\/", "/*/", command_line)

IPv4 and IPv6 addresses
re.sub(" [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", " *", new_command_line)
re.sub(" ([a-f0-9:]+:+)+[a-f0-9]+", " *", new_command_line)

Temp dirs created by installer
re.sub(“\/var\/folders\/[a-z0-9_]{2}\/[a-z0-9_]{30}\/[a-z]{1}\/“,”/*/“,new_command_line)

Interface names in ifconfig commands (most common way they would appear, doesn’t cover everything)
re.sub("ifconfig [a-z0-9]{3,10} ", "ifconfig * ", new_command_line)

Google Chrome stuff
re.sub(“\/tmp\/ksdownloadaction\.[a-z0-9]{10}/“,"/tmp/ksdownloadaction.*/",new_command_line)
re.sub(“\/tmp\/ksinstallaction\.[a-z0-9]{10}/","/tmp/ksinstallaction.*/",new_command_line)

UUIDs
re.sub(“-uuid [a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}”,"-uuid *",new_command_line)
```

Sample searches for finding a responsible process
```
# Look for an executable in the thread that isn't a built-in executable
# Find a process that doesn't start with `/usr/` or `/bin/*` or `/sbin/*`.
event.name:"process"
exec_chain.thread_uuid:("<thread_uuid>")
host.hostname:("<hostname>")
subject.process.name:"/*"
NOT (subject.process.name:("/usr/*" || "/bin/*" || "/sbin/*"))
GROUPBY TERM subject.process.name

# Look for a responsible process in the thread that isn't a built-in executable.
# Same query as above, but instead we're looking at the responsible process field.
event.name:"process"
exec_chain.thread_uuid:("<thread_uuid>")
host.hostname:("<hostname>")
subject.responsible_process_name:"/*"
NOT (subject.responsible_process_name:("/usr/*" || "/bin/*" || "/sbin/*"))
GROUPBY TERM subject.responsible_process_name

# Look for an open command or a shell command running a shell script.
# Commands like `open /Applications/Google Chrome.app` or `/bin/sh ashellscript.sh`.
event.name:"process"
exec_chain.thread_uuid:("<thread_uuid>")
host.hostname:("<hostname>")
(subject.responsible_process_name:"/usr/bin/open" ||
process.command_line:/\/bin\/[a-z]{0,5}sh .*/)
GROUPBY TERM process.command_line
```

config.py
```
cmds_list = []
cmds_list.append(
    {
        "command": "chmod",
        "process_arg_restrictions": 'process.args:("+x" || "777")'
    }
)
cmds_list.append(
    {
        "command": "chflags",
        "process_arg_restrictions": 'process.args:("hidden")'
    }
)
cmds_list.append(
    {
        "command": "getpwuid",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "hdiutil",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "ifconfig",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "ioreg",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "killall",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "kextload",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "kextunload",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "kextstat",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "kmutil",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "mdfind",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "pidinfo",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "security",
        "process_arg_restrictions": 'process.args:("add-trusted-cert" && "-d" && "-r" && "trustRoot" && "-k")',
    }
)
cmds_list.append(
    {
        "command": "security",
        "process_arg_restrictions": 'process.args:("default-keychain")'
    }
)
cmds_list.append(
    {
        "command": "scutil",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "sw_vers",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "sysctl",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "system_profiler",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "touch",
        "process_arg_restrictions": 'process.args:("-t")'
    }
)
cmds_list.append(
    {
        "command": "uname",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "uuidgen",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "whoami",
        "process_arg_restrictions": ""
    }
)
cmds_list.append(
    {
        "command": "xattr",
        "process_arg_restrictions": '(process.args:("com.apple.quarantine" && "-d") OR process.args:("-c"))'
    }
)
cmds_list.append(
    {
        "command": "xcode-select",
        "process_arg_restrictions": ""
    }
)
```


## Method 2 - Abnormally busy application trees
Nothing to publish here yet :)

## Method 3 - Application process trees running unexpected executables
Nothing to publish here yet :)
