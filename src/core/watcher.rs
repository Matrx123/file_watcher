use std::cmp;
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
    content_collection: HashMap<String, String>,
}

#[derive(Debug)]
pub enum FileStatus {
    Modified,
    NoChange,
    FileNotExist,
    NewFile,
}

#[derive(Debug, PartialEq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
}

#[derive(Debug, PartialEq)]
pub struct FileChanges {
    line_no: usize,
    message: String,
    change_type: ChangeType,
}

#[derive(Debug, PartialEq)]
pub struct FileChangeStatus {
    old_content: String,
    new_content: String,
    change_info: Vec<FileChanges>,
}

impl FileWatcher {
    pub fn new() -> Self {
        FileWatcher {
            hash_collection: HashMap::new(),
            content_collection: HashMap::new(),
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
                println!("\n :: File Status :: {:?}\n ", response);
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
        let new_content = read_to_string(path)?;

        match self.hash_collection.get(path) {
            Some(stored_hash) => {
                //evaluate hte store-hash with the calculated current hash
                if stored_hash == &current_hash {
                    Ok(FileStatus::NoChange)
                } else {
                    //check  old content  vs new content

                    if let Some(prev_content) = self.content_collection.get(path) {
                        let result = self.check_diff(prev_content, &new_content);
                        self.print_results(&result);
                    }

                    if let Some(value) = self.hash_collection.get_mut(path) {
                        *value = current_hash
                    }
                    //check for content
                    //new content and previous from the collection
                    if let Some(content) = self.content_collection.get_mut(path) {
                        *content = new_content
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

    pub fn print_results(&self, result: &FileChangeStatus) {
        println!("\n :: CHANGES ::\n");
        println!("::: Total changes = {:?} :::\n", result.change_info.len());

        //run loop to show lines
        for change in &result.change_info {
            println!("Line {} :: {:?}\n", change.line_no, change.change_type);
            println!("Content :: {:?}\n", change.message);
        }

        let added = &result
            .change_info
            .iter()
            .filter(|item| item.change_type == ChangeType::Added)
            .count();

        let removed = &result
            .change_info
            .iter()
            .filter(|item| item.change_type == ChangeType::Removed)
            .count();

        let modified = &result
            .change_info
            .iter()
            .filter(|item| item.change_type == ChangeType::Modified)
            .count();

        println!(
            "Added {} lines , Removed {} lines and Modified {} lines\n",
            added, removed, modified
        )
    }

    pub fn check_diff(&self, prev_content: &str, new_content: &str) -> FileChangeStatus {
        let old_lines: Vec<&str> = prev_content.lines().collect();
        let new_lines: Vec<&str> = new_content.lines().collect();

        let mut changes = Vec::new();
        let max_bound = cmp::max(old_lines.len(), new_lines.len());
        for i in 0..max_bound {
            match (old_lines.get(i), new_lines.get(i)) {
                (Some(old_item), Some(new_item)) => {
                    if old_item != new_item {
                        changes.push(FileChanges {
                            message: format!("--- {:?} \n +++ {:?}", old_item, new_item),
                            line_no: i + 1,
                            change_type: ChangeType::Modified,
                        })
                    }
                }
                (None, None) => break,
                (None, Some(new_item)) => changes.push(FileChanges {
                    line_no: i + 1,
                    change_type: ChangeType::Added,
                    message: format!("+++ {:?}\n", new_item),
                }),
                (Some(old_item), None) => changes.push(FileChanges {
                    line_no: i + 1,
                    change_type: ChangeType::Removed,
                    message: format!("--- {:?}\n", old_item),
                }),
            }
        }
        FileChangeStatus {
            old_content: prev_content.to_string(),
            new_content: new_content.to_string(),
            change_info: changes,
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
        hasher.update(&content);
        let result = hasher.finalize();
        let hashed_content = format!("{:x}", result);
        self.hash_collection
            .insert(path.unwrap().to_string(), hashed_content);
        self.content_collection
            .insert(path.unwrap().to_string(), content);
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
