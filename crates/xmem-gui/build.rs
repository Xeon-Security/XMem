//! Windows 실행 파일에 아이콘 리소스를 심는다.
//!
//! `-bins` 링크 인자만 쓰므로 테스트 바이너리는 리소스를 갖지 않는다.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let manifest_dir = PathBuf::from(manifest_dir);
    let icon_rc = manifest_dir.join("icon.rc");
    println!("cargo:rerun-if-changed={}", icon_rc.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("icon.ico").display()
    );

    if !cfg!(windows) {
        return;
    }
    let Some(rc) = find_rc() else {
        println!("cargo:warning=rc.exe를 찾지 못해 아이콘을 심지 못했습니다");
        return;
    };
    let Ok(out_dir) = std::env::var("OUT_DIR") else {
        return;
    };
    let out = PathBuf::from(out_dir).join("xmem-gui.res");
    let result = Command::new(&rc)
        .current_dir(&manifest_dir)
        .arg("/nologo")
        .arg("/fo")
        .arg(&out)
        .arg("icon.rc")
        .status();
    match result {
        Ok(status) if status.success() => {
            println!("cargo:rustc-link-arg-bins={}", out.display());
        }
        other => println!("cargo:warning=아이콘 리소스 컴파일 실패: {other:?}"),
    }
}

/// Windows Kits에서 최신 버전의 x64 rc.exe를 찾는다.
fn find_rc() -> Option<PathBuf> {
    let kits = std::env::var_os("ProgramFiles(x86)")?;
    let bin = Path::new(&kits).join("Windows Kits").join("10").join("bin");
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(bin)
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("x64").join("rc.exe"))
        .filter(|path| path.is_file())
        .collect();
    candidates.sort();
    candidates.pop()
}
