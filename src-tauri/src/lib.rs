// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

mod crypto_utils;
use crypto_utils::generate_rsa_keys;

#[tauri::command]
fn make_rsa_keys(key_size: usize) -> Result<(String, String), String> {
    match generate_rsa_keys(key_size) {
        Ok((private_key, public_key)) => Ok((private_key, public_key)),
        Err(e) => Err(format!("Error generating keys: {}", e)),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![make_rsa_keys])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
