use xmem_core::Heuristic;

/// 앞을 남기고 자른다. process 표에서 사용.
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

/// 뒤(파일명/경로 끝)를 남기고 자른다. mapped file 경로에서 사용.
pub(crate) fn truncate_tail(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_string();
    }
    let mut out = String::from("...");
    out.extend(text.chars().skip(count - max.saturating_sub(3)));
    out
}

/// 사람이 읽는 크기. 1024 미만은 B, 이상은 KiB/MiB/GiB (소수 1자리).
pub(crate) fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub(crate) fn heur_short(h: Heuristic) -> &'static str {
    match h {
        Heuristic::ExecutablePrivate => "exec-private",
        Heuristic::ExecutableAnonymous => "exec-anon",
        Heuristic::PrivateExecutablePeLike => "pe-like",
        Heuristic::WritableExecutable => "wx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_head() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
        assert_eq!(truncate("abcdefgh", 6), "abc...");
    }

    #[test]
    fn truncate_tail_keeps_tail() {
        assert_eq!(truncate_tail("abcdef", 6), "abcdef");
        assert_eq!(truncate_tail("abcdefgh", 6), "...fgh");
    }

    #[test]
    fn human_size_scales_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(4096), "4.0 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn heur_short_tags() {
        assert_eq!(heur_short(Heuristic::ExecutablePrivate), "exec-private");
        assert_eq!(heur_short(Heuristic::WritableExecutable), "wx");
    }
}
