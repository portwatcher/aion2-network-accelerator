use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub relay_addr: String,
    pub key_hex: String,
    pub vps_host: Option<String>,
    pub ssh_port: Option<u16>,
    pub ssh_user: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProfileStore {
    profiles: Vec<Profile>,
    active: Option<String>,
}

fn profiles_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| format!("Cannot resolve config dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create config dir: {e}"))?;
    Ok(dir.join("profiles.json"))
}

fn load_store(app: &AppHandle) -> Result<ProfileStore, String> {
    let path = profiles_path(app)?;
    if !path.exists() {
        return Ok(ProfileStore::default());
    }
    let data = std::fs::read_to_string(&path).map_err(|e| format!("Read profiles: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("Parse profiles: {e}"))
}

fn save_store(app: &AppHandle, store: &ProfileStore) -> Result<(), String> {
    let path = profiles_path(app)?;
    let data = serde_json::to_string_pretty(store).map_err(|e| format!("Serialize: {e}"))?;
    std::fs::write(&path, data).map_err(|e| format!("Write profiles: {e}"))
}

#[tauri::command]
pub async fn save_profile(app: AppHandle, profile: Profile) -> Result<(), String> {
    let mut store = load_store(&app)?;
    if let Some(existing) = store.profiles.iter_mut().find(|p| p.name == profile.name) {
        *existing = profile;
    } else {
        store.profiles.push(profile);
    }
    save_store(&app, &store)
}

#[tauri::command]
pub async fn load_profiles(app: AppHandle) -> Result<(Vec<Profile>, Option<String>), String> {
    let store = load_store(&app)?;
    Ok((store.profiles, store.active))
}

#[tauri::command]
pub async fn delete_profile(app: AppHandle, name: String) -> Result<(), String> {
    let mut store = load_store(&app)?;
    store.profiles.retain(|p| p.name != name);
    if store.active.as_deref() == Some(&name) {
        store.active = None;
    }
    save_store(&app, &store)
}

#[tauri::command]
pub async fn set_active_profile(app: AppHandle, name: String) -> Result<(), String> {
    let mut store = load_store(&app)?;
    if !store.profiles.iter().any(|p| p.name == name) {
        return Err(format!("Profile '{name}' not found"));
    }
    store.active = Some(name);
    save_store(&app, &store)
}
