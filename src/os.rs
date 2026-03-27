use std::process::{Command, Stdio};

/// Network information about the OS interface running the code.
/// Is fetched this way since it should not be stored on git.
pub struct OsInfo {
    pub interface: String,
    pub device_mac: [u8; 6],
    pub device_ip: [u8; 4],
}

impl OsInfo {
    /// Fetch the OS info.
    pub fn fetch() -> Result<Self, String> {
        let interface = Self::get_interface();
        let script = "./fetch_os.sh";
        let fetch_os_result = Command::new(script)
            .arg(&interface)
            .stdout(Stdio::piped())
            .output()
            .map_err(|e| format!("error with fetch script: {}", e))?;

        let fetch_stdout = String::from_utf8(fetch_os_result.stdout).map_err(|e| e.to_string())?;
        let [mac_string, ip_string]: [&str; 2] = fetch_stdout
            .trim()
            .splitn(2, ',')
            .collect::<Vec<&str>>()
            .try_into()
            .unwrap();

        println!("fetched device MAC {} and ip {}", mac_string, ip_string);

        let mac_addr: [u8; 6] = mac_string
            .splitn(6, ':')
            .map(|h| {
                u8::from_str_radix(h, 16)
                    .map_err(|e| format!("error parsing mac byte {:02x?}: {}", h, e))
                    .unwrap()
            })
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        let ip_addr: [u8; 4] = ip_string
            .splitn(4, '.')
            .map(|u| {
                u8::from_str_radix(u, 10)
                    .map_err(|e| format!("error parsing ip byte {}: {}", u, e))
                    .unwrap()
            })
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();

        Ok(Self {
            interface,
            device_mac: mac_addr,
            device_ip: ip_addr,
        })
    }

    /// Get the OS interface.
    pub fn get_interface() -> String {
        #[cfg(target_os = "macos")]
        let interface = "en0".to_string();
        #[cfg(target_os = "linux")]
        let interface = "enp0s8".to_string();

        interface
    }
}
