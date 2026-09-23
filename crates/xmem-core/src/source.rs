//! 데이터 출처 추상화: LiveProcess / Snapshot / Minidump / MemoryImage.

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_object_safe(_: &dyn MemorySource) {}
}
