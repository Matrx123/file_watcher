use std::collections::HashMap;
use std::error::Error;
use std::fs::read_to_string;
use std::path::Path;
use std::sync::mpsc::channel;

use notify::event::{CreateKind, DataChange, ModifyKind, RemoveKind, RenameMode};
use notify::{recommended_watcher, Event, EventKind, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};

pub struct FileWatcher {
    hash_collection: HashMap<String, String>,
}

#[derive(Debug)]
pub enum FileStatus {
    Modified,
    NoChange,
    FileNotExist,
    NewFile,
}

impl FileWatcher {
    pub fn new() -> Self {
        FileWatcher {
            hash_collection: HashMap::new(),
        }
    }

    pub fn check_status(&mut self) -> String {
        format!("Watcher up and running !!!")
    }

    fn handle_event(&mut self, event: Event) -> Result<(), Box<dyn Error>> {
        println!("=== EVENT START ===");
        // println!("Full Event :: {:?}", event);
        // println!("Event kind :: {:?}", event.kind);
        // println!("Event paths :: {:?}", event.paths);
        match event.kind {
            // EventKind::Access(AccessKind::Any) => {
            //     println!("");
            // }
            EventKind::Create(CreateKind::File) => {
                println!("File Created !!");
                self.hash_string(event.paths[0].to_str())?;
            }
            // EventKind::Create(CreateKind::Folder) => println!("Folder Created !!"),
            EventKind::Remove(RemoveKind::File) => {
                println!("File Removed !!");
                self.hash_collection
                    .remove_entry(event.paths[0].to_str().unwrap());
            }
            EventKind::Remove(RemoveKind::Folder) => println!("Folder Removed !!"),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)) => {
                let response = self.handle_content_change(event.paths[0].to_str().unwrap())?;
                println!("\n :: File Status :: {:?}\n", response);
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::Any)) => {
                // println!("\n :: Any event occured!! :: \n");
                //fire a rename handler function
                self.handle_rename_any(&event.paths[0])?;
            }
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                println!(
                    "Renamed from :: {:?} to :: {:?}",
                    event.paths[0], event.paths[1]
                );
            }
            _ => {
                // println!("\n:: Other event occurred!! ::\n");
            }
        }
        println!("=== EVENT END ===\n\n");
        Ok(())
    }

    pub fn handle_content_change(&mut self, path: &str) -> Result<FileStatus, Box<dyn Error>> {
        //if path does not exist, we will return FileStatsu file not found!!
        if !Path::new(path).exists() {
            return Ok(FileStatus::FileNotExist);
        }
        //calculate hte current hash, cehck in hashmap for a stored key-value pair
        let current_hash = self.calculate_currrent_hash(path)?;
        match self.hash_collection.get(path) {
            Some(stored_hash) => {
                //evaluate hte store-hash with the calculated current hash
                if stored_hash == &current_hash {
                    Ok(FileStatus::NoChange)
                } else {
                    if let Some(value) = self.hash_collection.get_mut(path) {
                        *value = current_hash
                    }
                    Ok(FileStatus::Modified)
                }
            }
            None => {
                //new file
                //calculate hash, for entry in the hashmap
                self.hash_string(Some(path))?;
                Ok(FileStatus::NewFile)
            }
        }
    }

    //create funtion to calculate the hash string
    pub fn calculate_currrent_hash(&mut self, path: &str) -> Result<String, Box<dyn Error>> {
        let content = read_to_string(path)?;

        let mut hasher = Sha256::new();
        hasher.update(content);
        let result = hasher.finalize();

        Ok(format!("{:x}", result))
    }

    pub fn handle_rename_any(&mut self, path: &Path) -> Result<(), Box<dyn Error>> {
        println!(
            "\n:: Path :: {:?} , Exists :: {:?}, is_file :: {:?} \n",
            path,
            path.exists(),
            path.is_file()
        );
        if path.exists() {
            //check if this si a file > hash it and store it in our hashmap
            if path.is_file() {
                self.hash_string(path.to_str())?;
                println!("\n Updated HashMap :: {:?}", self.hash_collection);
            } else {
                println!("\n:: Hey its not a file !!! ::\n");
            }
        } else {
            //remove the key-value pair
            self.hash_collection.remove_entry(path.to_str().unwrap());
            println!("\n Updated HashMap :: {:?}", self.hash_collection);
        }
        Ok(())
    }

    pub fn hash_string(&mut self, path: Option<&str>) -> Result<(), Box<dyn Error>> {
        let content = read_to_string(path.unwrap())?;

        // println!("Contents :: {:?}\n", content.trim());

        let mut hasher = Sha256::new();
        hasher.update(content);
        let result = hasher.finalize();
        let hashed_content = format!("{:x}", result);
        self.hash_collection
            .insert(path.unwrap().to_string(), hashed_content);

        println!("Hash Map store :: {:?}", self.hash_collection);

        Ok(())
    }

    pub fn start_monitoring(&mut self, path: &str) -> Result<(), Box<dyn Error>> {
        let (tx, rx) = channel();
        let mut watcher = recommended_watcher(tx)?;
        if let Err(e) = watcher.watch(Path::new(path), RecursiveMode::Recursive) {
            eprintln!("Error occured !! {:?}", e)
        }

        loop {
            let events = match rx.recv() {
                Ok(events) => events,
                Err(e) => {
                    eprintln!("Error occured !! {:?}", e);
                    break;
                }
            };
            match events {
                Ok(event) => {
                    if let Err(e) = self.handle_event(event) {
                        eprintln!("Error occured!! {:?}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error occured !! {:?}", e);
                    break;
                }
            }
        }
        Ok(())
    }
}
