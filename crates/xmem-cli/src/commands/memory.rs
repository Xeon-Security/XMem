use xmem_core::{MemoryRegion, ProcessInfo, RegionClass, Result, XmemError};
use xmem_memory::{LiveProcess, RegionMap};

use crate::cli::{GlobalArgs, MemoryCmd};
use crate::commands::render::{heur_short, human_size, truncate_tail};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(cmd: &MemoryCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        MemoryCmd::Map(pid_arg) => {
            let live = LiveProcess::open(pid_arg.pid)?;
            let map = live.region_map()?;
            match resolve_mode(global.json) {
                OutputMode::Json => {
                    let value =
                        serde_json::to_value(json_payload(&live.info, &map)).map_err(|e| {
                            XmemError::JsonError {
                                reason: e.to_string(),
                            }
                        })?;
                    emit_json(&success_envelope(value));
                    Ok(())
                }
                OutputMode::Human => {
                    print!("{}", render_map(&map));
                    Ok(())
                }
            }
        }
        MemoryCmd::Scan(_) => super::unimplemented("memory scan"),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MapSummary {
    total: usize,
    committed: usize,
    reserved: usize,
    free: usize,
    image: usize,
    mapped: usize,
    private: usize,
    executable: usize,
    heuristics: usize,
    committed_bytes: u64,
}

fn summarize(regions: &[MemoryRegion]) -> MapSummary {
    let mut s = MapSummary::default();
    for r in regions {
        s.total += 1;
        match r.classification {
            RegionClass::Image => {
                s.image += 1;
                s.committed += 1;
            }
            RegionClass::Mapped => {
                s.mapped += 1;
                s.committed += 1;
            }
            RegionClass::Private => {
                s.private += 1;
                s.committed += 1;
            }
            RegionClass::Free => s.free += 1,
            RegionClass::Reserved => s.reserved += 1,
            RegionClass::Unknown => {}
        }
        if r.classification != RegionClass::Free && r.classification != RegionClass::Reserved {
            s.committed_bytes = s.committed_bytes.saturating_add(r.size);
        }
        if r.executable {
            s.executable += 1;
        }
        s.heuristics += r.heuristics.len();
    }
    s
}

fn heur_list(region: &MemoryRegion) -> String {
    if region.heuristics.is_empty() {
        return "-".to_string();
    }
    region
        .heuristics
        .iter()
        .map(|h| heur_short(*h))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_map(map: &RegionMap) -> String {
    let mut out = String::new();
    out.push_str(
        "BASE               SIZE       STATE       TYPE        PROTECTION     CLASS      HEURISTICS     MAPPED FILE\n",
    );
    for r in &map.regions {
        let ty = match r.region_type {
            Some(t) => t.to_string(),
            None => "-".to_string(),
        };
        let mapped = match &r.mapped_file {
            Some(p) => truncate_tail(p, 48),
            None => "-".to_string(),
        };
        out.push_str(&format!(
            "0x{:016x} {:>10} {:11} {:11} {:14} {:10} {:14} {}\n",
            r.base,
            human_size(r.size),
            r.state.to_string(),
            ty,
            r.protection.to_string(),
            r.classification.to_string(),
            heur_list(r),
            mapped,
        ));
    }
    let s = summarize(&map.regions);
    out.push_str(&format!(
        "{} regions: committed {} ({}), reserved {}, free {}; image {}, mapped {}, private {}; executable {}; heuristics {}\n",
        s.total,
        s.committed,
        human_size(s.committed_bytes),
        s.reserved,
        s.free,
        s.image,
        s.mapped,
        s.private,
        s.executable,
        s.heuristics,
    ));
    if map.truncated {
        out.push_str("warning: region list truncated at MAX_REGIONS; results are incomplete\n");
    }
    out
}

fn json_payload(info: &ProcessInfo, map: &RegionMap) -> serde_json::Value {
    let s = summarize(&map.regions);
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "region_count": map.regions.len(),
        "truncated": map.truncated,
        "summary": {
            "total": s.total,
            "committed_count": s.committed,
            "reserved_count": s.reserved,
            "free_count": s.free,
            "image_count": s.image,
            "mapped_count": s.mapped,
            "private_count": s.private,
            "executable_count": s.executable,
            "heuristic_count": s.heuristics,
            "committed_bytes": s.committed_bytes,
        },
        "regions": map.regions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{MemoryState, MemoryType, Protection};

    fn region(base: u64, state: MemoryState, ty: Option<MemoryType>, raw: u32) -> MemoryRegion {
        let (r, w, x) = match raw {
            0x40 => (true, true, true),
            0x20 => (true, false, true),
            _ => (false, false, false),
        };
        let p = Protection::new(raw, r, w, x);
        MemoryRegion {
            base,
            size: 0x1000,
            state,
            protection: p,
            allocation_protection: None,
            region_type: ty,
            readable: p.readable,
            writable: p.writable,
            executable: p.executable,
            classification: xmem_core::classify(state, ty),
            heuristics: xmem_core::heuristics(state, &p, ty),
            mapped_file: None,
        }
    }

    fn sample_map() -> RegionMap {
        RegionMap {
            regions: vec![
                region(0x1000, MemoryState::Commit, Some(MemoryType::Private), 0x40),
                region(0x2000, MemoryState::Commit, Some(MemoryType::Image), 0x20),
                region(0x3000, MemoryState::Reserve, None, 0),
                region(0x4000, MemoryState::Free, None, 0),
            ],
            truncated: false,
        }
    }

    #[test]
    fn summary_counts_by_class() {
        let s = summarize(&sample_map().regions);
        assert_eq!(s.total, 4);
        assert_eq!((s.private, s.image, s.reserved, s.free), (1, 1, 1, 1));
        assert_eq!(s.executable, 2);
        assert_eq!(s.heuristics, 2);
        assert_eq!(s.committed_bytes, 0x2000);
    }

    #[test]
    fn render_map_has_header_rows_and_summary() {
        let out = render_map(&sample_map());
        assert!(out.contains("BASE"));
        assert!(out.contains("0x0000000000001000"));
        assert!(out.contains("MEM_PRIVATE"));
        assert!(out.contains("exec-private,wx"));
        assert!(out.contains("4 regions:"));
        assert!(!out.contains("truncated"));
    }

    #[test]
    fn render_map_warns_when_truncated() {
        let mut map = sample_map();
        map.truncated = true;
        assert!(render_map(&map).contains("truncated at MAX_REGIONS"));
    }

    #[test]
    fn json_payload_shape() {
        let info = ProcessInfo {
            pid: 42,
            ppid: None,
            name: "demo.exe".to_string(),
            image_path: None,
            arch: xmem_core::ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        };
        let value = json_payload(&info, &sample_map());
        assert_eq!(value["process"]["pid"], 42);
        assert_eq!(value["region_count"], 4);
        assert_eq!(value["truncated"], false);
        assert_eq!(value["summary"]["image_count"], 1);
        assert_eq!(value["regions"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn heur_list_renders_tags() {
        let r = region(0x1000, MemoryState::Commit, Some(MemoryType::Private), 0x40);
        assert_eq!(heur_list(&r), "exec-private,wx");
    }

    #[test]
    fn free_region_row_has_no_type_or_mapped_file() {
        let out = render_map(&sample_map());
        let line = out
            .lines()
            .find(|l| l.contains("0x0000000000004000"))
            .unwrap();
        assert!(line.contains("MEM_FREE"));
        assert!(line.contains(" free "));
    }
}
