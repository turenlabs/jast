mod backend;
mod investigation;
mod scanner;

use std::sync::Arc;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state = backend::AppState::open(&app.path().app_data_dir()?)?;
            app.manage(Arc::new(state));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            backend::get_settings,
            backend::set_threshold,
            backend::save_api_key,
            backend::remove_api_key,
            backend::select_repository,
            backend::start_scan,
            backend::list_scans,
            backend::get_scan,
            backend::get_evidence,
            backend::get_file_view,
            backend::get_preview_evidence,
            backend::cancel_scan,
            backend::resume_scan,
            backend::set_dismissed,
            backend::export_scan,
            backend::investigations::start_investigation,
            backend::investigations::get_investigation,
            backend::investigations::list_investigations,
            backend::investigations::get_active_investigation,
            backend::investigations::cancel_investigation
        ])
        .run(tauri::generate_context!())
        .expect("Unable to start JAST");
}
