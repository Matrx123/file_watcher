use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use chrono::Duration;

pub struct ProcessInfo {
    process_name: String,
    exc_path: Option<PathBuf>,
    pid: u32,
    cpu_usage: f32,
    mem_usage: f64,
}

pub struct ResourceMonitor {
    cpu_coll: HashMap<u32, VecDeque<f32>>,
    mem_coll: HashMap<u32, VecDeque<f64>>,
    cpu_threshold: f32,
    mem_threshold: f64,
    queue_bound: usize,
}

impl ResourceMonitor {
    pub fn new(cpu_threshold: f32, mem_threshold: f64, queue_bound: usize) -> Self {
        ResourceMonitor {
            cpu_coll: HashMap::new(),
            mem_coll: HashMap::new(),
            cpu_threshold,
            mem_threshold,
            queue_bound,
        }
    }
    //update collections
    pub fn modify_collections(&mut self, process_info: &ProcessInfo) {
        let cpu_queue = self
            .cpu_coll
            .entry(process_info.pid)
            .or_insert_with(|| VecDeque::new());
        cpu_queue.push_back(process_info.cpu_usage);
        //pop from front
        if cpu_queue.len() > self.queue_bound {
            cpu_queue.pop_front();
        }

        let mem_queue = self
            .mem_coll
            .entry(process_info.pid)
            .or_insert_with(|| VecDeque::new());
        mem_queue.push_back(process_info.mem_usage);
        if mem_queue.len() > self.queue_bound {
            mem_queue.pop_front();
        }
    }

    pub fn check_thresholds(&self, process_info: &ProcessInfo) -> Vec<String> {
        let mut warnings: Vec<String> = Vec::new();
        if process_info.cpu_usage > self.cpu_threshold {
            warnings.push(format!(
                "High CPU usage :: {:.2}%, surpassed {:.2}%",
                process_info.cpu_usage, self.cpu_threshold
            ))
        }

        if process_info.mem_usage > self.mem_threshold {
            warnings.push(format!(
                "High Memory usage :: {:.2}MB, surpassed {:.2}MB",
                process_info.mem_usage, self.mem_threshold
            ))
        }

        if let Some(cpu_item) = self.cpu_coll.get(&process_info.pid) {
            if cpu_item.len() > 4 {
                //sum/len
                let avg_cpu: f32 = cpu_item.iter().sum::<f32>() / cpu_item.len() as f32;
                if avg_cpu > self.cpu_threshold {
                    warnings.push(format!(
                        "Average cpu usage {:.2}% is higher than recommended one {:.2}%",
                        avg_cpu, self.cpu_threshold
                    ))
                }
            }
        }
        warnings
    }

    pub fn clear_pid(&mut self, terminated_pids: &HashSet<u32>) {
        self.cpu_coll
            .retain(|pid, _| !terminated_pids.contains(pid));
        self.mem_coll
            .retain(|pid, _| !terminated_pids.contains(pid));

        println!("collections :: {:?} :: {:?}", self.cpu_coll, self.mem_coll)
    }
}

pub struct ProcessMonitor {
    scan_interval: Duration,
    //resouce_monitor
}

impl ProcessMonitor {
    pub fn new(interval: Duration, cpu_threshold: f32, mem_threshold: f64) -> Self {
        ProcessMonitor {
            scan_interval: interval,
            //resource_monitor::new(cpu_th, mem_th)
        }
    }

    // pub fn watch_processes(&self) {}
}
