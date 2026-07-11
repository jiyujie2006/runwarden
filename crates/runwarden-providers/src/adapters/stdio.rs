use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use runwarden_kernel::ProviderManifest;

use super::{ExternalMcpRuntime, manifest_has_network_or_credentials};
use crate::executor::{ProviderExecutionRequest, ProviderExecutionResult};

/// Validate the static stdio contract, then fail closed until a mandatory OS
/// sandbox owns the child. A trusted path and a scrubbed environment are not
/// substitutes for scoped-root and egress enforcement when the downstream MCP
/// process itself is in the threat model.
pub(super) fn validate_registration(
    manifest: &ProviderManifest,
    trusted_runtime_root: &Path,
) -> Result<(), &'static str> {
    if manifest_has_network_or_credentials(manifest) {
        return Err("unsafe_stdio_egress");
    }
    if manifest.command_allowlist.len() != 1 {
        return Err("stdio_exact_command_required");
    }
    let command = &manifest.command_allowlist[0];
    if manifest.downstream_identity.as_deref() != Some(command)
        || !is_bare_command(command)
        || command_is_shell_capable(command)
    {
        return Err("stdio_exact_command_required");
    }
    if manifest.working_root.as_deref() != Some(".") {
        return Err("stdio_working_root_invalid");
    }
    validate_executable(trusted_runtime_root, command)?;

    // Plan 9 installs mandatory namespaces, Landlock/seccomp, cgroup ownership,
    // and deadline-safe output collection. There is deliberately no
    // unsandboxed compatibility fallback before then.
    Err("stdio_isolation_unavailable")
}

pub(super) fn execute(
    _manifest: &ProviderManifest,
    _request: &ProviderExecutionRequest,
    _runtime: &ExternalMcpRuntime<'_>,
) -> ProviderExecutionResult {
    ProviderExecutionResult::blocked("sandbox_unavailable", "stdio_isolation_unavailable")
}

fn validate_executable(root: &Path, command: &str) -> Result<PathBuf, &'static str> {
    let candidate = root.join(command);
    let metadata = fs::symlink_metadata(&candidate).map_err(|_| "adapter_executable_missing")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("adapter_executable_invalid");
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err("adapter_executable_not_executable");
    }
    let canonical = candidate
        .canonicalize()
        .map_err(|_| "adapter_executable_invalid")?;
    if canonical.parent() != Some(root) {
        return Err("adapter_executable_outside_runtime");
    }
    Ok(canonical)
}

fn is_bare_command(command: &str) -> bool {
    !command.is_empty()
        && Path::new(command).components().count() == 1
        && matches!(
            Path::new(command).components().next(),
            Some(Component::Normal(_))
        )
}

fn command_is_shell_capable(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "cmd"
            | "cmd.exe"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
    )
}

#[cfg(test)]
mod tests {
    use super::{command_is_shell_capable, is_bare_command};

    #[test]
    fn commands_are_single_bare_non_shell_identities() {
        assert!(is_bare_command("filesystem-mcp"));
        assert!(!is_bare_command("../filesystem-mcp"));
        assert!(!is_bare_command("bin/filesystem-mcp"));
        assert!(command_is_shell_capable("bash"));
        assert!(command_is_shell_capable("PowerShell.exe"));
        assert!(!command_is_shell_capable("filesystem-mcp"));
    }
}
