use std::io::stdin;
use std::path::Path;
use std::process;
use std::time::Duration;

mod core;

fn main() {
    let mut file_watcher = core::watcher::FileWatcher::new();
    let mut process_monitor =
        core::process_watcher::ProcessMonitor::new(Duration::new(20, 0), 90.00, 90.00, 5);
    let network_monitor = core::network_monitor::NetworkMonitor::new();
    eprintln!("Status :: {:?}", file_watcher.check_status());
    println!("::: WELCOME TO SCANGUARD :::\n\n +++ Enter the TARGET TYPE to watch!! +++ \n\n");

    // if let Err(e) = file_watcher.hash_string("/Users/vipin/Documents/test_folder/virus.txt") {
    //     eprintln!("Error occured, making an Exit !! {:?}", e);
    //     return;
    // }

    loop {
        let mut user_entry = String::new();

        match stdin().read_line(&mut user_entry) {
            Ok(_) => {
                if user_entry.trim().is_empty() {
                    println!("You have entered a empty input, please try again \n");
                    continue;
                } else {
                    match user_entry.trim().parse::<i32>() {
                        Ok(num) => {
                            println!("please enter a target type, you entered {} !!\n", num);
                            continue;
                        }
                        Err(_) => {
                            println!("user entered :: {:?}", user_entry.trim());
                            match user_entry.trim() {
                                "FILE" | "file" => {
                                    println!("Enter a file or directory to monitor !!\n");
                                    let mut user_path = String::new();
                                    match stdin().read_line(&mut user_path) {
                                        Ok(_) => {
                                            if user_path.trim().is_empty() {
                                                println!(
                                                    "Please enter a File or Directory to watch \n"
                                                );
                                                continue;
                                            }
                                            if Path::new(user_path.trim()).exists() {
                                                println!(
                                                    "Watching a Directory :: {:?}",
                                                    user_path.trim()
                                                );
                                                if let Err(e) = file_watcher
                                                    .start_monitoring(user_path.as_str().trim())
                                                {
                                                    eprintln!(
                                                        "Error occured, making an Exit !! {:?}\n",
                                                        e
                                                    );
                                                    break;
                                                }
                                            } else {
                                                println!("Directory or file does not existes!! \n");
                                                continue;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "\nError in reading the input path :: {:?}",
                                                e
                                            );
                                            process::exit(0);
                                        }
                                    }
                                }
                                "PROCESS" | "process" => {
                                    process_monitor.monitor_processes();
                                    break;
                                }
                                "NETWORK" | "network" => {
                                    network_monitor.start_scanning_network().unwrap();
                                    break;
                                }
                                _ => {
                                    println!("Please enter a valid target type!!\n");
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("\nError in reading the input :: {:?}", e);
                process::exit(0);
            }
        }
    }
}
