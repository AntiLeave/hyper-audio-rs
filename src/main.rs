use serde::Deserialize;
use std::env;
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
#[cfg(feature = "debug")]
use std::time::Instant;

fn pgrep_f(pattern: &str) -> Vec<i32> {
    Command::new("pgrep")
        .args(["-f", pattern])
        .stderr(Stdio::null())
        .output()
        .ok()
        .into_iter()
        .flat_map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn set_realtime_priority(pid: i32, prio: i32) {
    unsafe {
        let param = libc::sched_param {
            sched_priority: prio,
        };
        libc::sched_setscheduler(pid, libc::SCHED_FIFO, &param);
    }
}

#[cfg(not(target_os = "linux"))]
fn set_realtime_priority(_pid: i32, _prio: i32) {}

#[allow(dead_code)]
fn boost(pattern: &str) {
    let pids = pgrep_f(pattern);
    for pid in pids {
        let _ = fs::write("/dev/cpuset/top-app/cgroup.procs", format!("{}\n", pid));
        set_realtime_priority(pid, 10);
    }
}

struct BoostTidRule<'a> {
    process: &'a str,
    threads: &'a str,
}

fn boost_tid(rules: &[BoostTidRule<'_>]) {
    let compiled: Vec<(regex::Regex, regex::Regex)> = rules
        .iter()
        .filter_map(|r| {
            let pr = regex::Regex::new(r.process).ok()?;
            let tr = regex::Regex::new(&format!("^(?:{})$", r.threads)).ok()?;
            Some((pr, tr))
        })
        .collect();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let _pid: i32 = match entry.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let cmdline = match fs::read_to_string(entry.path().join("cmdline")) {
            Ok(s) => s.replace('\0', " "),
            Err(_) => continue,
        };

        let matching_thread_res: Vec<&regex::Regex> = compiled
            .iter()
            .filter_map(|(pr, tr)| pr.is_match(&cmdline).then_some(tr))
            .collect();

        if matching_thread_res.is_empty() {
            continue;
        }

        let task_dir = match fs::read_dir(entry.path().join("task")) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for task_entry in task_dir.flatten() {
            let tid: i32 = match task_entry.file_name().to_string_lossy().parse() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let comm = match fs::read_to_string(task_entry.path().join("comm")) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let comm = comm.trim();
            if !matching_thread_res.iter().any(|r| r.is_match(comm)) {
                continue;
            }
            let _ = fs::write("/dev/cpuset/top-app/tasks", format!("{}\n", tid));
            set_realtime_priority(tid, 10);
        }
    }
}

fn is_low_latency_audio() -> bool {
    let output = match Command::new("dumpsys")
        .args(["media.audio_flinger"])
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found = false;
    let mut output_type: Option<u32> = None;
    let mut standby = false;

    for line in stdout.lines() {
        if line.starts_with("Historical Thread Log") {
            break;
        }

        if line.starts_with("Output thread") {
            output_type = None;
            standby = false;
            found = false;
            if line.contains("type 0 (MIXER)") {
                output_type = Some(0);
            } else if line.contains("type 5 (MMAP_PLAYBACK)") {
                output_type = Some(5);
            }
            continue;
        }

        if line.contains("Standby: yes") {
            standby = true;
            continue;
        }
        if line.contains("Standby: no") {
            standby = false;
            continue;
        }

        match output_type {
            Some(0) => {
                if standby {
                    continue;
                }
                if let Some(rest) = line.split("activeMask=0x").nth(1) {
                    let mask = rest.split_whitespace().next().unwrap_or("");
                    #[cfg(feature = "debug")]
                    eprintln!("{}", line);
                    if mask != "0" && mask != "00" {
                        found = true;
                        break;
                    }
                }
            }
            Some(5) => {
                if standby {
                    continue;
                }
                let trimmed = line.trim_start();
                if !trimmed.contains(" Tracks") {
                    continue;
                }
                let rest = trimmed.split(" Tracks").next().unwrap_or("");
                #[cfg(feature = "debug")]
                eprintln!("{}", line);
                if rest.parse::<u32>().unwrap_or(0) > 0 {
                    found = true;
                    break;
                }
            }
            _ => {}
        }
    }

    found
}

fn get_foreground_activity() -> Option<String> {
    let procs = fs::read_to_string("/dev/cpuset/top-app/cgroup.procs").ok()?;
    for pid_str in procs.split_whitespace() {
        let pid: i32 = pid_str.parse().ok()?;
        if !is_normal_app(pid) {
            continue;
        }
        if !is_visible(pid) {
            continue;
        }
        let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok()?;
        let name = cmdline.split('\0').next()?;
        let pkg = name.split(':').next()?;
        return Some(pkg.to_string());
    }
    None
}

fn is_visible(pid: i32) -> bool {
    let s = match fs::read_to_string(format!("/proc/{}/oom_score_adj", pid)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.trim().parse::<i32>().unwrap_or(1000) == 0
}

fn is_normal_app(pid: i32) -> bool {
    let status = match fs::read_to_string(format!("/proc/{}/status", pid)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if !line.starts_with("Uid:") {
            continue;
        }
        if let Some(uid_str) = line.split_whitespace().nth(1) {
            if let Ok(uid) = uid_str.parse::<u32>() {
                return uid >= 10000;
            }
        }
        return false;
    }
    false
}

fn is_screen_on() -> bool {
    let output = match Command::new("dumpsys")
        .args(["deviceidle", "get", "screen"])
        .stderr(Stdio::null())
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.contains("true")
}

#[cfg(feature = "cirrus")]
fn switch_cirrus_dsp(bypass_dsp: bool) {
    let _ = Command::new("tinymix")
        .args([
            "B PCM Source",
            if bypass_dsp { "ASPRX1" } else { "DSP" },
        ]);
    let _ = Command::new("tinymix")
        .args([
            "T PCM Source",
            if bypass_dsp { "ASPRX1" } else { "DSP" },
        ]);
}

#[derive(Deserialize)]
struct Config {
    enable: bool,
    #[serde(default)]
    only_whitelist: bool,
    #[cfg(feature = "cirrus")]
    #[serde(default)]
    bypass_cirrus_dsp: bool,
    #[serde(default)]
    whitelist: Vec<String>,
}

fn load_config() -> Option<Config> {
    let dir = env::current_exe().ok()?.parent()?.to_path_buf();
    let path = dir.join("config.toml");
    let content = fs::read_to_string(&path).ok()?;
    toml::from_str(&content).ok()
}

fn main() {
    let config = match load_config() {
        Some(c) if c.enable => c,
        _ => {
            eprintln!("config.toml not found or enable=false, exiting");
            return;
        }
    };

    let mut prev_foreground = String::new();

    loop {
        let foreground = get_foreground_activity().unwrap_or_default();

        if !foreground.is_empty() && foreground != prev_foreground {
            prev_foreground = foreground.clone();
            eprintln!("foreground changed: {}", foreground);
            #[cfg(feature = "cirrus")]
            if config.bypass_cirrus_dsp {
                switch_cirrus_dsp(false);
            }
            thread::sleep(Duration::from_secs(5));

            #[cfg(feature = "debug")]
            let start = Instant::now();
            let foreground2 = get_foreground_activity().unwrap_or_default();
            #[cfg(feature = "debug")]
            eprintln!("activity elapsed: {:?}", start.elapsed());

            if foreground2 == prev_foreground {
                let in_whitelist = config.whitelist.iter().any(|w| w == &foreground);
                let should_boost = if in_whitelist {
                    eprintln!("foreground in whitelist, boost audio");
                    true
                } else if config.only_whitelist {
                    false
                } else if is_low_latency_audio() {
                    eprintln!("Low latency audio is active, boost audio");
                    true
                } else {
                    false
                };
                if should_boost {
                    #[cfg(feature = "debug")]
                    let start = Instant::now();
                    boost_tid(&[
                        BoostTidRule { process: "audioserver",         threads: "FastMixer|Audio.*Out_.*|AAudio_.*|binder:.*" },
                        BoostTidRule { process: "audiohalservice.qti", threads: "low_latency_out|raw_out_.*|mmap_no_irq_out" },
                        BoostTidRule { process: &foreground,           threads: "AudioTrack|AAudio_.*|FMOD mixer.*" },
                    ]);
                    #[cfg(feature = "debug")]
                    eprintln!("audio elapsed: {:?}", start.elapsed());
                }
                #[cfg(feature = "cirrus")]
                if in_whitelist {
                    if config.bypass_cirrus_dsp {
                        switch_cirrus_dsp(true);
                    }
                }
            }
        }

        thread::sleep(Duration::from_secs(2));

        while !is_screen_on() {
            thread::sleep(Duration::from_secs(5));
        }
    }
}
