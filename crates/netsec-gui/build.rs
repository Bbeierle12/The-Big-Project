fn main() {
    // Re-compile when webview assets change (include_str! is compile-time)
    println!("cargo:rerun-if-changed=assets/webview/widget.js");
    println!("cargo:rerun-if-changed=assets/webview/index.html");
}
