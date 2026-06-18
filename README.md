# Solexjay 2026 Sysmon Configuration

## A patched and extended fork of sysmon-modular by Olaf Hartong

This repository contains a working Sysmon configuration based on the widely-used
[sysmon-modular](https://github.com/olafhartong/sysmon-modular) project by Olaf
Hartong, with a documented set of fixes and original detection additions layered
on top. This is **not presented as an original work from scratch** — the base
configuration represents years of community-driven detection engineering, and it
deserves credit. What's documented below is exactly what changed, what was fixed,
and what original detection logic was added, so the delta is fully transparent and
verifiable against the upstream source.

---

## Attribution

- **Base configuration:** [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
  (medium verbosity / balanced release)
- **Patches, fixes, and original additions:** Solomon James ([github.com/Jaysolex](https://github.com/Jaysolex))
- **Schema version:** 4.90 (current — verified against Sysmon v15.20, June 2026 release)

All original additions in the XML are tagged with `Solexjay-2026` in either the
`name` attribute or an inline XML comment immediately above the block, so every
change can be located with a single search: `grep -n "Solexjay" sysmonconfig.xml`

---

## Why this fork exists

This was built as part of an ongoing detection engineering portfolio
([Detection-Content](https://github.com/Jaysolex/Detection-Content)) — a
repository of 31+ Sigma, Splunk SPL, and Microsoft Sentinel KQL rules mapped to
real APT campaigns. Several of those rules depend on specific Sysmon telemetry
that the base sysmon-modular config does not fully operationalize at the
collection layer. This fork closes that gap: the Sysmon config now collects the
exact signal those detection rules expect to see.

---

## 1. Audit Findings (Issues Identified in the Base Config)

### 1.1 Exact duplicate rule entry (fixed)

Line 2638–2639 of the original file contained the **exact same line twice** inside
the same `RuleGroup`:

```xml
<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="is">wab.exe</Image>
<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="is">wab.exe</Image>
```

This is a no-op duplicate — it doesn't break anything, but it adds dead weight to
every rule evaluation cycle for every process creation event on the host. **Fixed**
by removing the redundant second line and replacing it with a comment noting the
fix.

### 1.2 Schema version — verified current

Schema `4.90` was checked against Sysmon's current release (v15.20, June 2026) and
confirmed to be the current schema version. **No change needed here** — this was
verified, not assumed.

### 1.3 Missing post-2023 LOLBins

The base config has strong, comprehensive coverage of classic LOLBins (regsvr32,
rundll32, mshta, certutil, bitsadmin, msiexec, and dozens more) but did not include
several binaries that have become relevant abuse vectors more recently:

| Binary | Why it matters |
|---|---|
| `winget.exe` | Windows Package Manager — can be abused to silently install attacker-hosted packages, a technique seen increasingly since 2023 |
| `pnputil.exe` | Driver installation utility — abused for driver-based persistence and signed-driver loading attacks |
| `wt.exe` (Windows Terminal) | Newer terminal host, an alternate execution surface to cmd.exe/powershell.exe that's frequently un-monitored |
| `PubPrn.vbs` / `SyncAppvPublishingServer.vbs` | Signed Microsoft scripts usable for proxy execution (LOLBAS-documented, T1216) |

**Fixed** — five new entries added to the existing `T1218`/`T1216` System Binary
Proxy Execution block.

### 1.4 Cloud-sync abuse — zero detection coverage (real blind spot)

This was the most significant gap found. Searching the entire file for
OneDrive/Dropbox/cloud-sync logic returned **only exclusion rules** — every single
reference to OneDrive, Dropbox, or related sync processes exists purely to reduce
noise from legitimate sync traffic.

There was **no detection logic at all** for a well-documented technique: an
attacker stages sensitive files (credential stores, archives, documents) directly
into a user's local OneDrive/Dropbox sync folder, and the cloud provider
exfiltrates the data automatically and silently over an encrypted, trusted
channel — completely bypassing network DLP and egress monitoring, because to the
network the traffic looks identical to normal personal cloud sync.

**Fixed** — added a new `FileCreate` include `RuleGroup` (`Solexjay-2026-CloudSyncExfil`)
specifically watching for archives, credential stores, and bulk document staging
into known cloud-sync folder paths.

### 1.5 Process Tampering (Event ID 25) — exclude-only, no targeted include

The base config's `ProcessTampering` section contains only an `exclude` list (for
known-noisy legitimate software like Firefox, Git, Edge). There is no explicit
`include` logic prioritizing the specific LOLBins most commonly used as process
hollowing or herpaderping injection targets.

**Fixed** — added a new `ProcessTampering` include `RuleGroup`
(`Solexjay-2026-ProcessTamperingInclude`) targeting explorer.exe, svchost.exe,
rundll32.exe, powershell.exe, mshta.exe, and notepad.exe as known hollowing/
herpaderping targets.

---

## 2. Original Detections Added (Tied to Real APT Research)

These three detections are not generic — they are built directly from threat
intelligence research and rule development done for the
[Detection-Content](https://github.com/Jaysolex/Detection-Content) repository,
where each technique is documented with full APT attribution, SOC investigation
playbooks, and Sigma/Splunk/KQL equivalents.

### 2.1 Kimsuky-style Registry Run Key Persistence

```xml
<Rule name="Solexjay-2026,technique_id=T1547.001,technique_name=Kimsuky-style reg.exe Run Key Persistence" groupRelation="and">
  <OriginalFileName condition="is">reg.exe</OriginalFileName>
  <CommandLine condition="contains any">CurrentVersion\Run;CurrentVersion\RunOnce</CommandLine>
  <ParentImage condition="contains any">cmd.exe;powershell.exe;wscript.exe;cscript.exe;hh.exe;mshta.exe</ParentImage>
</Rule>
```

Kimsuky (APT43) is documented writing Base64-obfuscated VBScript to
`HKCU\...\Run` via `reg.exe ADD`, typically as the final stage after CHM, HTA, or
ISO-based initial access. This rule fires specifically when `reg.exe` modifies a
Run key **and** was spawned by a script host or weaponized-document-execution
binary — the exact chain documented in Detection-Content Rules #28/#29.

### 2.2 ISO / Mark of the Web Bypass — Execution from Mounted Drive

```xml
<Rule name="Solexjay-2026,technique_id=T1553.005,technique_name=ISO MOTW Bypass - Script Host From Mounted Drive" groupRelation="and">
  <Image condition="begin with">D:\</Image>
  <Image condition="contains any">powershell.exe;cmd.exe;wscript.exe;cscript.exe;mshta.exe</Image>
</Rule>
```

(Mirrored for `E:\` as well.) Files inside a mounted ISO do not inherit the Mark
of the Web (Zone.Identifier ADS) of the parent ISO file — a technique used
heavily by Kimsuky and commodity loaders (Emotet, QakBot, Bumblebee) since
Microsoft's 2022 macro-blocking policy pushed attackers toward container-based
delivery. Legitimate enterprise software almost never executes from non-system
drive letters, making this a very high-confidence, low-noise detection. Documented
in Detection-Content Rules #26/#26b.

### 2.3 CHM Weaponization — hh.exe Spawning Script Interpreters

```xml
<Rule name="Solexjay-2026,technique_id=T1218.001,technique_name=CHM Weaponization - hh.exe Child Process" groupRelation="and">
  <ParentImage condition="end with">hh.exe</ParentImage>
  <Image condition="contains any">powershell.exe;cmd.exe;wscript.exe;cscript.exe;mshta.exe;certutil.exe;bitsadmin.exe;regsvr32.exe;rundll32.exe;wmic.exe;reg.exe;schtasks.exe</Image>
</Rule>
```

`hh.exe` (Windows Help) is a signed Microsoft binary that has no legitimate reason
to spawn a script interpreter, download cradle, or task/WMI utility. This single
parent-child relationship is one of the highest-confidence detections in the
entire configuration, and is mapped in Detection-Content's APT-grade Rule #25 to
six confirmed threat actors: **APT41, APT37, Kimsuky, Bitter APT, Silence APT, and
DeathStalker.**

---

## 3. What Was Deliberately NOT Changed

In keeping with an honest delta, the following were **left exactly as-is**:

- All 34 original `RuleGroup` blocks and their logic
- All existing technique tagging and MITRE ATT&CK references
- The ASCII banner and attribution comment crediting Olaf Hartong
- The schema version (confirmed current, not arbitrarily bumped)
- All existing exclude rules (legitimate noise reduction is left untouched —
  only new include logic was added where coverage was missing)

---

## 4. Deployment Notes (2026)

- Sysmon is now natively integrated into Windows 11 and Windows Server 2025 as an
  optional feature (Windows 11 KB5079473, March 2026), receiving updates through
  standard Windows servicing. Standalone Sysmon and built-in Sysmon are **not**
  supported side-by-side — check for an existing install before enabling the
  native feature.
- Standalone Sysmon remains the right choice for systems where the built-in
  feature is unavailable (older Windows versions, unsupported builds).
- Apply with: `sysmon64 -c solexjay_2026_sysmonconfig.xml` (standalone) or via your
  existing GPO/Intune/endpoint management deployment for the built-in feature.
- The new `Solexjay-2026-CloudSyncExfil` rule will generate volume in
  environments with heavy legitimate OneDrive/Dropbox archive usage (e.g., IT
  teams routinely zipping logs into synced folders). Tune the exclude list for
  your environment's known-legitimate archive-to-cloud workflows before wide
  deployment.

---

## 5. Verification

This patched configuration was validated for well-formed XML and confirmed via
diff against the unmodified original to ensure:

- Zero original lines were altered or deleted (except the one intentional
  duplicate removal documented in 1.1)
- All additions are clearly tagged and isolated
- The file parses cleanly under Python's `xml.etree.ElementTree` and follows
  Sysmon schema 4.90 structure

---

## Credits

- **Olaf Hartong** — original sysmon-modular project and the vast majority of
  detection logic in this configuration: https://github.com/olafhartong/sysmon-modular
- **Solomon James (Jaysolex)** — audit, fixes, and original APT-mapped detection
  additions documented above: https://github.com/Jaysolex
