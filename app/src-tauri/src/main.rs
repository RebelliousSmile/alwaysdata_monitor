// Pas de console Windows en plus de la fenêtre dans un build release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    vigie_console_lib::run()
}
