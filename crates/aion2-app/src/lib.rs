mod deploy;
mod profiles;
mod proxy;

use proxy::ProxyState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(ProxyState::default())
        .invoke_handler(tauri::generate_handler![
            proxy::start_proxy,
            proxy::stop_proxy,
            proxy::get_status,
            deploy::deploy_relay,
            profiles::save_profile,
            profiles::load_profiles,
            profiles::delete_profile,
            profiles::set_active_profile,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
