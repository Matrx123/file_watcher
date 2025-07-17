mod core;

fn main() {
    let mut file_watcher = core::watcher::FileWatcher::new();
    eprintln!("Status :: {:?}", file_watcher.check_status());

    // if let Err(e) = file_watcher.hash_string("/Users/vipin/Documents/test_folder/virus.txt") {
    //     eprintln!("Error occured, making an Exit !! {:?}", e);
    //     return;
    // }

    if let Err(e) = file_watcher.start_monitoring("/Users/vipin/Documents/test_folder/") {
        eprintln!("Error occured, making an Exit !! {:?}", e);
        return;
    }
}
