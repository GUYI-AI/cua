//! ElectronJS: detect Electron apps and evaluate JS via CDP inspector.

use std::collections::HashSet;
use std::time::Duration;

use super::cdp_client::{listening_ports, CdpClient};

pub struct ElectronJs;

impl ElectronJs {
    /// Returns true if the process at `pid` is an Electron app.
    pub fn is_electron(pid: i32) -> bool {
        // This runs before native AX presses. Enumerating every running app
        // here used to fork plist readers for every bundle on every click,
        // holding the global input coordinator for seconds under load.
        // The kernel's executable for this exact pid is sufficient.
        crate::apps::path_of_pid(pid)
            .is_some_and(|path| executable_is_electron(std::path::Path::new(&path)))
    }

    /// Evaluate JavaScript in the Electron app's main (Node.js) process at
    /// `pid` through its inspector, opening it with SIGUSR1 when no inspector
    /// is listening yet. Apps built with the inspector fuse off refuse.
    pub async fn execute_main(javascript: &str, pid: i32) -> anyhow::Result<String> {
        let existing_ports = listening_ports(pid).await;
        for &port in &existing_ports {
            if CdpClient::is_node_inspector(port).await {
                return CdpClient::evaluate_node(javascript, port).await;
            }
        }
        unsafe {
            libc::kill(pid, libc::SIGUSR1);
        }
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            for port in listening_ports(pid).await {
                if !existing_ports.contains(&port) && CdpClient::is_node_inspector(port).await {
                    return CdpClient::evaluate_node(javascript, port).await;
                }
            }
        }
        anyhow::bail!("no Node inspector for Electron pid {pid} (the app may disable it)")
    }

    /// Evaluate JavaScript in the Electron app at `pid` via CDP.
    pub async fn execute(javascript: &str, pid: i32) -> anyhow::Result<String> {
        // Only inspect listeners owned by the requested process. Probing common
        // CDP ports globally can execute JavaScript in an unrelated browser.
        let existing_ports = listening_ports(pid).await;
        for &port in &existing_ports {
            if CdpClient::is_available(port).await {
                return CdpClient::evaluate(javascript, port).await;
            }
        }

        // Snapshot current ports, then send SIGUSR1 to open the inspector.
        let before_ports: HashSet<u16> = existing_ports.iter().cloned().collect();

        unsafe {
            libc::kill(pid, libc::SIGUSR1);
        }

        // Poll for a new process-owned port.
        let mut new_port: Option<u16> = None;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let current = listening_ports(pid).await;
            for &p in &current {
                if !before_ports.contains(&p) && CdpClient::is_available(p).await {
                    new_port = Some(p);
                    break;
                }
            }
            if new_port.is_some() {
                break;
            }
        }

        let port = new_port.ok_or_else(|| {
            anyhow::anyhow!(
                "Could not find Electron inspector port for pid {pid}. \
                             Try launching with --inspect or --remote-debugging-port."
            )
        })?;

        CdpClient::evaluate(javascript, port).await
    }
}

/// Detect the framework beside this executable, including nonstandard install
/// locations. Never infer another process's bundle from a display name.
fn executable_is_electron(executable: &std::path::Path) -> bool {
    let Some(macos) = executable
        .parent()
        .filter(|p| p.ends_with("Contents/MacOS"))
    else {
        return false;
    };
    macos.parent().is_some_and(|contents| {
        contents
            .join("Frameworks/Electron Framework.framework")
            .is_dir()
    })
}

#[cfg(test)]
mod tests {
    use super::executable_is_electron;

    #[test]
    fn identifies_the_exact_bundle_in_a_nonstandard_install_location() {
        let dir = tempfile::tempdir().unwrap();
        let contents = dir.path().join("Trial Apps/聊天客户端.app/Contents");
        std::fs::create_dir_all(contents.join("Frameworks/Electron Framework.framework")).unwrap();
        assert!(executable_is_electron(&contents.join("MacOS/Chat")));
    }

    #[test]
    fn another_bundle_with_the_same_name_cannot_classify_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let electron = dir.path().join("Electron/Calculator.app/Contents");
        let native = dir.path().join("Native/Calculator.app/Contents");
        std::fs::create_dir_all(electron.join("Frameworks/Electron Framework.framework")).unwrap();
        std::fs::create_dir_all(native.join("MacOS")).unwrap();
        assert!(executable_is_electron(&electron.join("MacOS/Calculator")));
        assert!(!executable_is_electron(&native.join("MacOS/Calculator")));
    }

    #[test]
    fn unrelated_framework_and_missing_executable_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Frameworks/Electron Framework.framework"))
            .unwrap();
        assert!(!executable_is_electron(&dir.path().join("bin/tool")));
        assert!(!executable_is_electron(std::path::Path::new("")));
    }
}
