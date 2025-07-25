use core::f64;
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};

use sysinfo::{Pid, Process, System};

pub struct ProcessInfo {
    process_name: String,
    exc_path: Option<PathBuf>,
    pid: u32,
    cpu_usage: f32,
    mem_usage: f64,
}

#[derive(Debug)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Warning,
    Info,
}

#[derive(Debug)]
pub enum AlertType {
    ThreatDetected {
        pid: u32,
        process_name: String,
        threat_type: AlertSeverity,
    },
    HighResourceUssage {
        pid: u32,
        process_name: String,
        cpu_usage: f32,
        mem_usage: f64,
    },
    NewProcessAlert {
        pid: u32,
        process_name: String,
        details: String,
    },
    SystemAlert {
        message: String,
    },
}

pub struct Alert {
    severity: AlertSeverity,
    alert_type: AlertType,
    detail: String,
    timestamp: f64,
}

pub trait AlertHandler {
    fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn Error>>;
}

pub struct ConsoleAlertsHandler;

impl AlertHandler for ConsoleAlertsHandler {
    fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn Error>> {
        println!(
            "{:?} An {:?} with severity of {:?} is there, \n details :: {:?}",
            alert.timestamp, alert.alert_type, alert.severity, alert.detail
        );
        Ok(())
    }
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
                        "Average cpu usage :: {:.2}% is higher than recommended :: {:.2}%",
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
    resource_monitor: ResourceMonitor,
    alert_handlers: Vec<Box<dyn AlertHandler>>,
    system: System,
    previous_processes: HashMap<u32, ProcessInfo>,
}

impl ProcessMonitor {
    pub fn new(interval: Duration, cpu_threshold: f32, mem_threshold: f64, bound: usize) -> Self {
        let mut process_monitor = ProcessMonitor {
            scan_interval: interval,
            resource_monitor: ResourceMonitor::new(cpu_threshold, mem_threshold, bound),
            //threat detector
            alert_handlers: Vec::new(),
            system: System::new_all(),
            previous_processes: HashMap::new(),
        };

        process_monitor.add_alert_handlers(Box::new(ConsoleAlertsHandler));
        //file handler
        //notification handler
        process_monitor
    }

    pub fn send_alert(&self, alert: &Alert) {
        for handler in &self.alert_handlers {
            if let Err(e) = handler.handle_alert(alert) {
                eprintln!("Error occured while handling alerts :: {:?}", e);
            }
        }
    }

    pub fn add_alert_handlers(&mut self, alert_handler: Box<dyn AlertHandler>) {
        self.alert_handlers.push(alert_handler)
    }

    pub fn get_process_info(&self, pid: &Pid, process: &Process) -> ProcessInfo {
        ProcessInfo {
            process_name: format!("{:?}", process.name()),
            pid: pid.as_u32(),
            cpu_usage: process.cpu_usage(),
            mem_usage: process.memory() as f64,
            exc_path: process.exe().map(|item| item.to_path_buf()),
        }
    }

    pub fn check_process(&mut self, process_info: &ProcessInfo) {
        //check or analyze the process for threats and memory and cpu usages
        //threats, ProcessManager > Alert
        // if error  = threat_detector(process_info) > alert

        self.resource_monitor.modify_collections(process_info);
        let warnings = self.resource_monitor.check_thresholds(process_info);
        if !warnings.is_empty() {
            //raise alert
        }
    }

    pub fn detect_new_process(&self, processes: &HashMap<u32, ProcessInfo>) {
        for (pid, _) in processes {
            if !self.previous_processes.contains_key(pid) {
                //its a new process
                //alert terminal from here
            }
        }
    }

    pub fn scan_processes(&mut self) -> Result<(), Box<dyn Error>> {
        let mut current_process: HashMap<u32, ProcessInfo> = HashMap::new();
        let mut current_pids: HashSet<u32> = HashSet::new();
        //scan all the processes
        self.system.refresh_all();
        for (pid, process) in self.system.processes() {
            let process_info = self.get_process_info(pid, process);
            current_pids.insert(process_info.pid);
            current_process.insert(process_info.pid, process_info);
        }

        for process_info in current_process.values() {
            self.check_process(process_info);
        }
        //detect new processes
        self.detect_new_process(&current_process);
        //update the collections
        //clear the collection
        self.resource_monitor.clear_pid(&current_pids);

        self.previous_processes = current_process;
        Ok(())
    }

    pub fn monitor_processes(&mut self) {
        println!("::: Process scanning starts :::\n");

        loop {
            let now = Instant::now();
            if let Err(e) = self.scan_processes() {
                println!("Error occured on scanning processes :: {:?}", e);
            }
            let elapsed = now.elapsed();
            if elapsed < self.scan_interval {
                sleep(self.scan_interval - elapsed)
            }
        }
    }
}
