
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("icons/icon.ico");
        res.compile().unwrap_or_else(|e| eprintln!("winresource: {}", e));
    }
    tauri_build::build()
}
