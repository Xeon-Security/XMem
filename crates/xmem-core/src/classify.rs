use crate::model::{Heuristic, MemoryState, MemoryType, Protection, RegionClass};

/// Windows state/type 조합을 연구용 분류로 변환한다. 사실(관찰)이며 해석이 아니다.
pub fn classify(state: MemoryState, region_type: Option<MemoryType>) -> RegionClass {
    match state {
        MemoryState::Free => RegionClass::Free,
        MemoryState::Reserve => RegionClass::Reserved,
        MemoryState::Commit => match region_type {
            Some(MemoryType::Image) => RegionClass::Image,
            Some(MemoryType::Mapped) => RegionClass::Mapped,
            Some(MemoryType::Private) => RegionClass::Private,
            None => RegionClass::Unknown,
        },
    }
}

/// 분류 힌트. Detection Rule의 입력으로만 사용하며 악성 판정이 아니다.
pub fn heuristics(
    state: MemoryState,
    protection: &Protection,
    region_type: Option<MemoryType>,
) -> Vec<Heuristic> {
    let mut out = Vec::new();
    if state == MemoryState::Commit && protection.executable {
        if region_type == Some(MemoryType::Private) {
            out.push(Heuristic::ExecutablePrivate);
        }
        if protection.writable {
            out.push(Heuristic::WritableExecutable);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prot(raw: u32, r: bool, w: bool, x: bool) -> Protection {
        Protection::new(raw, r, w, x)
    }

    #[test]
    fn classify_maps_state_and_type() {
        assert_eq!(classify(MemoryState::Free, None), RegionClass::Free);
        assert_eq!(classify(MemoryState::Reserve, None), RegionClass::Reserved);
        assert_eq!(
            classify(MemoryState::Commit, Some(MemoryType::Image)),
            RegionClass::Image
        );
        assert_eq!(
            classify(MemoryState::Commit, Some(MemoryType::Mapped)),
            RegionClass::Mapped
        );
        assert_eq!(
            classify(MemoryState::Commit, Some(MemoryType::Private)),
            RegionClass::Private
        );
        assert_eq!(classify(MemoryState::Commit, None), RegionClass::Unknown);
    }

    #[test]
    fn heuristics_flags_private_executable_first() {
        let hs = heuristics(
            MemoryState::Commit,
            &prot(0x40, true, true, true),
            Some(MemoryType::Private),
        );
        assert_eq!(
            hs,
            vec![Heuristic::ExecutablePrivate, Heuristic::WritableExecutable]
        );
    }

    #[test]
    fn heuristics_executable_private_without_write() {
        let hs = heuristics(
            MemoryState::Commit,
            &prot(0x20, true, false, true),
            Some(MemoryType::Private),
        );
        assert_eq!(hs, vec![Heuristic::ExecutablePrivate]);
    }

    #[test]
    fn heuristics_writable_executable_for_image() {
        let hs = heuristics(
            MemoryState::Commit,
            &prot(0x40, true, true, true),
            Some(MemoryType::Image),
        );
        assert_eq!(hs, vec![Heuristic::WritableExecutable]);
    }

    #[test]
    fn heuristics_ignore_non_executable_and_non_commit() {
        assert!(
            heuristics(
                MemoryState::Commit,
                &prot(0x04, true, true, false),
                Some(MemoryType::Private)
            )
            .is_empty()
        );
        assert!(
            heuristics(
                MemoryState::Reserve,
                &prot(0x40, true, true, true),
                Some(MemoryType::Private)
            )
            .is_empty()
        );
        assert!(heuristics(MemoryState::Free, &prot(0x01, false, false, false), None).is_empty());
    }
}
