//! Read-only external-provider manifest loading and certification.
//!
//! Executable MCP transports are intentionally absent from this public
//! module. They are crate-private and reachable only through
//! `DefaultProviderExecutor`.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path};

use runwarden_kernel::{
    ProviderClass, ProviderContract, ProviderKind, ProviderManifest, ProviderRisk, SideEffectKind,
};
use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExternalProviderCertReport {
    pub passed: bool,
    pub findings: Vec<String>,
    pub contract: ProviderContract,
    pub side_effect_executed: bool,
}

pub fn load_provider_manifest(input: &str) -> serde_json::Result<ProviderManifest> {
    serde_json::from_str(input)
}

pub fn certify_external_provider_manifest(
    manifest: &ProviderManifest,
) -> ExternalProviderCertReport {
    let contract = ProviderContract::from_manifest(manifest);
    let mut findings = Vec::new();

    if manifest.provider_class != ProviderClass::External {
        findings.push("provider_class_must_be_external".to_owned());
    }
    if !manifest.provider_id.starts_with("external.") {
        findings.push("external_provider_id_prefix_required".to_owned());
    }
    if manifest.schema_pin.algorithm != "sha256" {
        findings.push("schema_pin_algorithm_unsupported".to_owned());
    }
    if manifest.schema_pin.digest != runwarden_kernel::schema_digest(&manifest.schema_pin.schema) {
        findings.push("schema_pin_digest_mismatch".to_owned());
    }
    if contract.schema_rug_pull_detected {
        findings.push("schema_rug_pull".to_owned());
    }
    if manifest.declared_permissions.is_empty() {
        findings.push("declared_permissions_required".to_owned());
    }

    match manifest.kind {
        ProviderKind::Mcp => certify_mcp_manifest(manifest, &mut findings),
        ProviderKind::Shell => certify_shell_manifest(manifest, &mut findings),
        ProviderKind::Plugin | ProviderKind::Skill => {
            if manifest.tool_identity.is_none() {
                findings.push("tool_identity_required".to_owned());
            }
        }
        ProviderKind::Api | ProviderKind::Scanner | ProviderKind::Enterprise => {
            if manifest.allowed_origins.is_empty() {
                findings.push("egress_policy_required".to_owned());
            }
        }
        _ => findings.push("external_provider_kind_not_supported".to_owned()),
    }

    if requires_egress(manifest) && manifest.allowed_origins.is_empty() {
        findings.push("egress_policy_required".to_owned());
    }
    findings.sort();
    findings.dedup();
    ExternalProviderCertReport {
        passed: findings.is_empty(),
        findings,
        contract,
        side_effect_executed: false,
    }
}

fn certify_mcp_manifest(manifest: &ProviderManifest, findings: &mut Vec<String>) {
    match manifest.transport.as_deref() {
        Some("stdio") => {
            if manifest.command_allowlist.len() != 1 {
                findings.push("stdio_exact_command_required".to_owned());
            } else {
                let command = &manifest.command_allowlist[0];
                if manifest.downstream_identity.as_deref() != Some(command)
                    || !is_bare_command(command)
                    || command_is_shell_capable(command)
                {
                    findings.push("stdio_exact_command_required".to_owned());
                }
            }
            if manifest.working_root.as_deref() != Some(".") {
                findings.push("stdio_working_root_invalid".to_owned());
            }
            if !manifest
                .side_effects
                .contains(&SideEffectKind::ProcessSpawn)
                || !manifest
                    .declared_permissions
                    .iter()
                    .any(|permission| permission == "process_spawn")
            {
                findings.push("stdio_process_spawn_declaration_required".to_owned());
            }
            if stdio_requires_unsupported_egress_controls(manifest) {
                findings.push("stdio_egress_controls_unsupported".to_owned());
            }
        }
        Some("http" | "sse") => {
            if manifest.allowed_origins.is_empty() {
                findings.push("egress_policy_required".to_owned());
            }
            if !manifest.command_allowlist.is_empty() || manifest.working_root.is_some() {
                findings.push("network_transport_process_controls_forbidden".to_owned());
            }
            if manifest
                .allowed_origins
                .iter()
                .any(|origin| !is_canonical_public_plain_http_origin(origin))
            {
                findings.push("network_transport_origin_invalid".to_owned());
            }
        }
        _ => findings.push("mcp_transport_required".to_owned()),
    }
    if manifest.downstream_identity.is_none() {
        findings.push("downstream_identity_required".to_owned());
    }
    if manifest.tool_identity.is_none() {
        findings.push("tool_identity_required".to_owned());
    }
}

fn certify_shell_manifest(manifest: &ProviderManifest, findings: &mut Vec<String>) {
    if manifest.command_allowlist.is_empty() {
        findings.push("shell_command_allowlist_required".to_owned());
    }
    if manifest.working_root.is_none() {
        findings.push("shell_working_root_required".to_owned());
    }
    if manifest.risk == ProviderRisk::Destructive
        && !manifest.side_effects.contains(&SideEffectKind::Destructive)
    {
        findings.push("destructive_side_effect_required".to_owned());
    }
}

fn requires_egress(manifest: &ProviderManifest) -> bool {
    matches!(
        manifest.risk,
        ProviderRisk::NetworkActive | ProviderRisk::CredentialUse
    ) || manifest.side_effects.contains(&SideEffectKind::Network)
        || matches!(manifest.transport.as_deref(), Some("http" | "sse"))
}

fn stdio_requires_unsupported_egress_controls(manifest: &ProviderManifest) -> bool {
    requires_egress(manifest)
        || manifest
            .side_effects
            .contains(&SideEffectKind::CredentialUse)
        || !manifest.allowed_origins.is_empty()
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

pub(crate) fn is_canonical_public_plain_http_origin(origin: &str) -> bool {
    let Ok(url) = Url::parse(origin) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    url.scheme() == "http"
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.origin().ascii_serialization() == origin
        && host.parse::<IpAddr>().map_or(true, is_public_ip)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ipv4(mapped);
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || (segments[0] & 0xffc0 == 0xfec0)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_documentation()
        && !ip.is_multicast()
        && octets[0] != 0
        && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
        && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        && !(octets[0] == 198 && (18..=19).contains(&octets[1]))
        && octets[0] < 240
}
