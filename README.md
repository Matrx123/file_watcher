# 🔍 File Watcher

A comprehensive **Rust** application for system monitoring and security that provides **file system monitoring**, **process tracking**, and **network scanning** capabilities.

---

## ✨ Features

- 📁 **File System Monitoring** — Monitor files and directories for changes using the [`notify`](https://crates.io/crates/notify) crate
- 🔄 **Process Monitoring** — Track system processes and resource usage
- 🌐 **Network Scanning** — Basic network monitoring and scanning functionality

---

## 🛠️ Prerequisites

- 🦀 Rust (latest stable version)
- 📦 Cargo package manager

---

## ⚡ Installation

### 1. Clone the repository
```bash
git clone https://github.com/matrix123/file_watcher.git
```

### 2. Navigate into the project directory
```bash
cd file_watcher
```

### 3. Build the project
```bash
cargo build
```

### 4. Run the project
```bash
cargo run
```

---

## 🚀 Usage

When running the application, you can choose one of the following monitoring options:

### 1️⃣ 📁 FILE — Monitor file system changes
- Enter `FILE` or `file` when prompted
- Provide the path to the file or directory you want to monitor

### 2️⃣ ⚙️ PROCESS — Monitor system processes
- Enter `PROCESS` or `process` when prompted
- Monitor CPU and memory usage

### 3️⃣ 🌐 NETWORK — Network scanning
- Enter `NETWORK` or `network` when prompted
- Perform basic network monitoring

---

## 📝 Logging
- Process monitoring results are saved in **`process.log`**


---

## 📚 Dependencies

- [notify](https://crates.io/crates/notify) — For file system monitoring
- Other standard Rust libraries

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. 🔀 Fork the repository  
2. 🌿 Create your feature branch  
   ```bash
   git checkout -b feature/YourFeatureName
   ```
3. ✍️ Commit your changes  
   ```bash
   git commit -m "Add YourFeatureName"
   ```
4. 🚀 Push to the branch  
   ```bash
   git push origin feature/YourFeatureName
   ```
5. 📫 Create a new Pull Request  

---

Built with ❤️ using **Rust** 🦀
