# 使用 Go 语言在 Windows 上开发简易 PM2 式进程守护系统

下面我将为您详细讲解如何使用 Go 语言在 Windows 上开发一个类似 PM2 的进程守护系统。这个系统将包含核心功能如进程启动、停止、重启、监控和日志管理。

## 系统架构设计

```
+-------------------+     +-----------------+     +-----------------+
|  命令行客户端      |     |  守护进程       |     |  被守护进程     |
| (pm2-win-cli)    |<--->| (pm2-win-daemon)|---->| (your-app.exe)  |
+-------------------+     +-----------------+     +-----------------+
       ↑                       ↑ ↑                       ↑
       |                       | |                       |
+-------------------+     +-----------------+     +-----------------+
|  用户交互         |     |  进程管理       |     |  子进程         |
|  命令解析         |     |  监控重启       |     |  执行实际任务    |
|  状态显示         |     |  日志管理       |     +-----------------+
+-------------------+     |  RPC服务        |
                          +-----------------+
```

## 完整实现代码

### 1. 守护进程主程序 (`daemon/main.go`)

```go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	serviceName = "PM2WinDaemon"
	daemonPort  = 9999
)

var (
	installFlag   = flag.Bool("install", false, "Install service")
	uninstallFlag = flag.Bool("uninstall", false, "Uninstall service")
	runFlag       = flag.Bool("run", false, "Run in console mode")
)

func main() {
	flag.Parse()
	
	if *installFlag {
		installService()
		return
	}
	
	if *uninstallFlag {
		uninstallService()
		return
	}
	
	if *runFlag {
		runConsoleMode()
		return
	}
	
	// 检查是否在服务环境中运行
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("Failed to determine if running as service: %v", err)
	}
	
	if isService {
		runService()
	} else {
		fmt.Println("Please run as service or with --run flag")
		os.Exit(1)
	}
}

func runConsoleMode() {
	log.Println("Running in console mode")
	startDaemon()
}

func runService() {
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		log.Fatalf("Failed to open event log: %v", err)
	}
	defer elog.Close()
	
	elog.Info(1, "Starting service")
	
	if err := svc.Run(serviceName, &serviceHandler{elog: elog}); err != nil {
		elog.Error(1, fmt.Sprintf("Service failed: %v", err))
		return
	}
	
	elog.Info(1, "Service stopped")
}

func startDaemon() {
	log.Println("PM2Win Daemon starting")
	
	// 创建进程管理器
	pm := NewProcessManager()
	
	// 启动RPC服务器
	go startRPCServer(pm)
	
	// 启动监控器
	go pm.StartMonitor()
	
	// 启动Web界面
	go startWebUI(pm)
	
	log.Println("Daemon is ready. Listening on port", daemonPort)
	
	// 等待退出信号
	quit := make(chan os.Signal, 1)
	<-quit
	pm.StopAll()
	log.Println("Daemon stopped")
}

func installService() {
	exePath, err := filepath.Abs(os.Args[0])
	if err != nil {
		log.Fatal(err)
	}
	
	mgr, err := svc.Mgr.Connect()
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Disconnect()
	
	// 创建服务
	config := svc.Config{
		DisplayName: "PM2Win Daemon",
		Description: "Process manager for Windows similar to PM2",
		StartType:   svc.StartAutomatic,
	}
	
	service, err := mgr.CreateService(serviceName, exePath, config)
	if err != nil {
		log.Fatal("CreateService failed:", err)
	}
	defer service.Close()
	
	// 设置恢复策略
	recoveryActions := []svc.RecoveryAction{
		{Type: svc.ServiceRestart, Delay: 60 * time.Second},
		{Type: svc.ServiceRestart, Delay: 120 * time.Second},
		{Type: svc.NoAction},
	}
	
	if err := service.SetRecoveryActions(recoveryActions, 86400); err != nil {
		log.Println("Warning: failed to set recovery actions:", err)
	}
	
	// 创建事件日志源
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		log.Println("Warning: failed to create event source:", err)
	}
	
	log.Println("Service installed successfully")
}

func uninstallService() {
	mgr, err := svc.Mgr.Connect()
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Disconnect()
	
	service, err := mgr.OpenService(serviceName)
	if err != nil {
		log.Fatal("Service not installed:", err)
	}
	defer service.Close()
	
	// 停止服务
	if status, err := service.Control(svc.Stop); err == nil {
		timeout := time.Now().Add(10 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(timeout) {
			time.Sleep(500 * time.Millisecond)
			status, err = service.Query()
			if err != nil {
				break
			}
		}
	}
	
	// 删除服务
	if err := service.Delete(); err != nil {
		log.Fatal("DeleteService failed:", err)
	}
	
	// 移除事件日志源
	if err := eventlog.Remove(serviceName); err != nil {
		log.Println("Warning: failed to remove event source:", err)
	}
	
	log.Println("Service uninstalled successfully")
}

type serviceHandler struct {
	elog *eventlog.Log
}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	
	// 启动守护逻辑
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go func() {
		startDaemon()
		cancel()
	}()
	
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				return false, 0
			case svc.Interrogate:
				changes <- c.CurrentStatus
			}
		case <-ctx.Done():
			return false, 0
		}
	}
}
```

### 2. 进程管理器 (`daemon/process_manager.go`)

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ProcessConfig 进程配置
type ProcessConfig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Command     string   `json:"command"`
	Args        []string `json:"args"`
	WorkingDir  string   `json:"working_dir"`
	Restart     bool     `json:"restart"`
	MaxRestarts int      `json:"max_restarts"`
	LogFile     string   `json:"log_file"`
}

// ProcessStatus 进程状态
type ProcessStatus struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"` // running, stopped, restarting
	PID         int       `json:"pid"`
	Restarts    int       `json:"restarts"`
	StartTime   time.Time `json:"start_time"`
	Uptime      string    `json:"uptime"`
	CPU         float64   `json:"cpu"`
	Memory      uint64    `json:"memory"`
}

// Process 被守护的进程
type Process struct {
	Config ProcessConfig
	Status ProcessStatus
	cmd    *exec.Cmd
	mu     sync.Mutex
	stopCh chan struct{}
	log    *os.File
}

// ProcessManager 进程管理器
type ProcessManager struct {
	processes map[string]*Process
	mu        sync.RWMutex
}

func NewProcessManager() *ProcessManager {
	return &ProcessManager{
		processes: make(map[string]*Process),
	}
}

// StartProcess 启动新进程
func (pm *ProcessManager) StartProcess(cfg ProcessConfig) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if _, exists := pm.processes[cfg.ID]; exists {
		return fmt.Errorf("process with ID %s already exists", cfg.ID)
	}
	
	process := &Process{
		Config: cfg,
		Status: ProcessStatus{
			ID:        cfg.ID,
			Name:      cfg.Name,
			Status:    "starting",
			StartTime: time.Now(),
		},
		stopCh: make(chan struct{}),
	}
	
	// 设置日志文件
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %v", err)
		}
		process.log = logFile
	}
	
	pm.processes[cfg.ID] = process
	
	// 启动进程
	go process.Run()
	
	return nil
}

// StopProcess 停止进程
func (pm *ProcessManager) StopProcess(id string) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	process, exists := pm.processes[id]
	if !exists {
		return fmt.Errorf("process with ID %s not found", id)
	}
	
	return process.Stop()
}

// RestartProcess 重启进程
func (pm *ProcessManager) RestartProcess(id string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	process, exists := pm.processes[id]
	if !exists {
		return fmt.Errorf("process with ID %s not found", id)
	}
	
	// 先停止
	if err := process.Stop(); err != nil {
		return err
	}
	
	// 重置状态
	process.Status.Status = "restarting"
	process.Status.Restarts = 0
	
	// 重新启动
	go process.Run()
	
	return nil
}

// ListProcesses 列出所有进程
func (pm *ProcessManager) ListProcesses() []ProcessStatus {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	statuses := make([]ProcessStatus, 0, len(pm.processes))
	for _, proc := range pm.processes {
		proc.mu.Lock()
		status := proc.Status
		proc.mu.Unlock()
		
		// 更新运行时间
		if status.Status == "running" {
			status.Uptime = time.Since(status.StartTime).Round(time.Second).String()
		}
		
		// TODO: 获取CPU和内存使用率
		
		statuses = append(statuses, status)
	}
	
	return statuses
}

// GetProcessStatus 获取单个进程状态
func (pm *ProcessManager) GetProcessStatus(id string) (ProcessStatus, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	process, exists := pm.processes[id]
	if !exists {
		return ProcessStatus{}, fmt.Errorf("process with ID %s not found", id)
	}
	
	process.mu.Lock()
	defer process.mu.Unlock()
	
	status := process.Status
	if status.Status == "running" {
		status.Uptime = time.Since(status.StartTime).Round(time.Second).String()
	}
	
	return status, nil
}

// StopAll 停止所有进程
func (pm *ProcessManager) StopAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	for id, proc := range pm.processes {
		if err := proc.Stop(); err != nil {
			log.Printf("Failed to stop process %s: %v", id, err)
		}
		delete(pm.processes, id)
	}
}

// StartMonitor 启动监控器
func (pm *ProcessManager) StartMonitor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		pm.mu.RLock()
		for _, proc := range pm.processes {
			proc.mu.Lock()
			if proc.Status.Status == "running" {
				// 检查进程是否存活
				if proc.cmd.ProcessState != nil && proc.cmd.ProcessState.Exited() {
					proc.Status.Status = "stopped"
					
					// 如果需要重启
					if proc.Config.Restart && 
						(proc.Config.MaxRestarts == 0 || proc.Status.Restarts < proc.Config.MaxRestarts) {
						proc.Status.Restarts++
						go proc.Run()
					}
				}
			}
			proc.mu.Unlock()
		}
		pm.mu.RUnlock()
	}
}

// Run 运行进程
func (p *Process) Run() {
	p.mu.Lock()
	p.Status.Status = "starting"
	p.Status.StartTime = time.Now()
	p.mu.Unlock()
	
	for {
		select {
		case <-p.stopCh:
			return
		default:
			// 创建命令
			cmd := exec.Command(p.Config.Command, p.Config.Args...)
			
			// 设置工作目录
			if p.Config.WorkingDir != "" {
				cmd.Dir = p.Config.WorkingDir
			}
			
			// 设置输出
			if p.log != nil {
				cmd.Stdout = p.log
				cmd.Stderr = p.log
			}
			
			p.mu.Lock()
			p.cmd = cmd
			p.Status.PID = cmd.Process.Pid
			p.Status.Status = "running"
			p.mu.Unlock()
			
			// 启动进程
			if err := cmd.Start(); err != nil {
				log.Printf("Failed to start process %s: %v", p.Config.ID, err)
				
				p.mu.Lock()
				p.Status.Status = "stopped"
				p.mu.Unlock()
				return
			}
			
			log.Printf("Process %s started with PID %d", p.Config.ID, cmd.Process.Pid)
			
			// 等待进程退出
			err := cmd.Wait()
			
			p.mu.Lock()
			if err != nil {
				log.Printf("Process %s exited with error: %v", p.Config.ID, err)
			} else {
				log.Printf("Process %s exited normally", p.Config.ID)
			}
			
			// 检查是否应该重启
			if !p.Config.Restart {
				p.Status.Status = "stopped"
				p.mu.Unlock()
				return
			}
			
			if p.Config.MaxRestarts > 0 && p.Status.Restarts >= p.Config.MaxRestarts {
				p.Status.Status = "stopped"
				p.mu.Unlock()
				return
			}
			
			p.Status.Restarts++
			p.mu.Unlock()
			
			// 延迟重启
			time.Sleep(5 * time.Second)
		}
	}
}

// Stop 停止进程
func (p *Process) Stop() error {
	close(p.stopCh)
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	
	// 先尝试正常终止
	if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
		log.Printf("Failed to send interrupt to process %s: %v", p.Config.ID, err)
	}
	
	// 等待5秒
	timeout := time.After(5 * time.Second)
	done := make(chan error, 1)
	go func() {
		_, err := p.cmd.Process.Wait()
		done <- err
	}()
	
	select {
	case <-timeout:
		// 强制终止
		if err := p.cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill process: %v", err)
		}
	case <-done:
	}
	
	p.Status.Status = "stopped"
	
	// 关闭日志文件
	if p.log != nil {
		p.log.Close()
	}
	
	return nil
}
```

### 3. RPC 服务器 (`daemon/rpc_server.go`)

```go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// RPCRequest RPC请求
type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	ID     int             `json:"id"`
}

// RPCResponse RPC响应
type RPCResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
	ID     int         `json:"id"`
}

// RPC方法处理
type RPCHandler struct {
	pm *ProcessManager
}

func startRPCServer(pm *ProcessManager) {
	handler := &RPCHandler{pm: pm}
	
	http.HandleFunc("/rpc", func(w http.ResponseWriter, r *http.Request) {
		var req RPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		
		var resp RPCResponse
		resp.ID = req.ID
		
		switch strings.ToLower(req.Method) {
		case "start":
			var cfg ProcessConfig
			if err := json.Unmarshal(req.Params, &cfg); err != nil {
				resp.Error = "Invalid params"
			} else {
				if err := pm.StartProcess(cfg); err != nil {
					resp.Error = err.Error()
				} else {
					resp.Result = "Process started"
				}
			}
			
		case "stop":
			var id string
			if err := json.Unmarshal(req.Params, &id); err != nil {
				resp.Error = "Invalid params"
			} else {
				if err := pm.StopProcess(id); err != nil {
					resp.Error = err.Error()
				} else {
					resp.Result = "Process stopped"
				}
			}
			
		case "restart":
			var id string
			if err := json.Unmarshal(req.Params, &id); err != nil {
				resp.Error = "Invalid params"
			} else {
				if err := pm.RestartProcess(id); err != nil {
					resp.Error = err.Error()
				} else {
					resp.Result = "Process restarted"
				}
			}
			
		case "list":
			resp.Result = pm.ListProcesses()
			
		case "status":
			var id string
			if err := json.Unmarshal(req.Params, &id); err != nil {
				resp.Error = "Invalid params"
			} else {
				status, err := pm.GetProcessStatus(id)
				if err != nil {
					resp.Error = err.Error()
				} else {
					resp.Result = status
				}
			}
			
		default:
			resp.Error = "Method not found"
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})
	
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", daemonPort))
	if err != nil {
		log.Fatalf("Failed to start RPC server: %v", err)
	}
	
	log.Printf("RPC server listening on %s", listener.Addr())
	
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("RPC server failed: %v", err)
	}
}
```

### 4. Web 管理界面 (`daemon/web_ui.go`)

```go
package main

import (
	"fmt"
	"net/http"
	"text/template"
)

func startWebUI(pm *ProcessManager) {
	// 静态文件服务
	fs := http.FileServer(http.Dir("web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	
	// 主页
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("web/templates/index.html")
		if err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
			return
		}
		
		data := struct {
			Processes []ProcessStatus
		}{
			Processes: pm.ListProcesses(),
		}
		
		tmpl.Execute(w, data)
	})
	
	// API端点
	http.HandleFunc("/api/processes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pm.ListProcesses())
	})
	
	// 启动Web服务器
	port := 8080
	log.Printf("Web UI available at http://localhost:%d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
```

### 5. 命令行客户端 (`client/pm2-win-cli.go`)

```go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

type Client struct {
	ServerURL string
}

func NewClient() *Client {
	return &Client{
		ServerURL: "http://localhost:9999/rpc",
	}
}

func (c *Client) Call(method string, params interface{}) (interface{}, error) {
	request := map[string]interface{}{
		"method": method,
		"params": params,
		"id":     1,
	}
	
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	
	resp, err := http.Post(c.ServerURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var rpcResp struct {
		Result interface{} `json:"result"`
		Error  string      `json:"error"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, err
	}
	
	if rpcResp.Error != "" {
		return nil, fmt.Errorf(rpcResp.Error)
	}
	
	return rpcResp.Result, nil
}

func main() {
	startCmd := flag.NewFlagSet("start", flag.ExitOnError)
	startID := startCmd.String("id", "", "Process ID")
	startName := startCmd.String("name", "", "Process name")
	startCmd := startCmd.String("cmd", "", "Command to execute")
	startArgs := startCmd.String("args", "", "Command arguments (comma separated)")
	startDir := startCmd.String("dir", "", "Working directory")
	startLog := startCmd.String("log", "", "Log file path")
	
	stopCmd := flag.NewFlagSet("stop", flag.ExitOnError)
	stopID := stopCmd.String("id", "", "Process ID")
	
	restartCmd := flag.NewFlagSet("restart", flag.ExitOnError)
	restartID := restartCmd.String("id", "", "Process ID")
	
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: pm2-win-cli <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  start   - Start a new process")
		fmt.Println("  stop    - Stop a process")
		fmt.Println("  restart - Restart a process")
		fmt.Println("  list    - List all processes")
		os.Exit(1)
	}
	
	client := NewClient()
	
	switch os.Args[1] {
	case "start":
		startCmd.Parse(os.Args[2:])
		if *startID == "" || *startCmd == "" {
			fmt.Println("ID and command are required")
			os.Exit(1)
		}
		
		args := []string{}
		if *startArgs != "" {
			args = strings.Split(*startArgs, ",")
		}
		
		config := map[string]interface{}{
			"id":          *startID,
			"name":        *startName,
			"command":     *startCmd,
			"args":        args,
			"working_dir": *startDir,
			"log_file":    *startLog,
			"restart":     true,
			"max_restarts": 10,
		}
		
		result, err := client.Call("start", config)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(result)
		
	case "stop":
		stopCmd.Parse(os.Args[2:])
		if *stopID == "" {
			fmt.Println("ID is required")
			os.Exit(1)
		}
		
		result, err := client.Call("stop", *stopID)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(result)
		
	case "restart":
		restartCmd.Parse(os.Args[2:])
		if *restartID == "" {
			fmt.Println("ID is required")
			os.Exit(1)
		}
		
		result, err := client.Call("restart", *restartID)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(result)
		
	case "list":
		listCmd.Parse(os.Args[2:])
		result, err := client.Call("list", nil)
		if err != nil {
			log.Fatal(err)
		}
		
		processes := result.([]interface{})
		fmt.Println("ID\tName\tStatus\tPID\tRestarts\tUptime")
		for _, p := range processes {
			proc := p.(map[string]interface{})
			fmt.Printf("%s\t%s\t%s\t%d\t%d\t%s\n",
				proc["id"], proc["name"], proc["status"], 
				int(proc["pid"].(float64)), int(proc["restarts"].(float64)), 
				proc["uptime"])
		}
		
	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}
```

## 系统功能详解

### 1. 守护进程 (`daemon/main.go`)

- **服务管理**:
  - `installService()`: 将守护进程安装为 Windows 服务
  - `uninstallService()`: 卸载服务
  - `runService()`: 作为 Windows 服务运行
  - `runConsoleMode()`: 控制台模式运行（调试用）

- **核心功能**:
  - `startDaemon()`: 启动守护主逻辑
  - `serviceHandler`: Windows 服务处理接口实现

### 2. 进程管理器 (`daemon/process_manager.go`)

- **数据结构**:
  - `ProcessConfig`: 进程配置（ID、命令、参数、日志文件等）
  - `ProcessStatus`: 进程状态（PID、状态、重启次数等）
  - `Process`: 被守护的进程实例
  - `ProcessManager`: 管理所有进程的中央控制器

- **核心方法**:
  - `StartProcess()`: 根据配置启动新进程
  - `StopProcess()`: 停止指定进程
  - `RestartProcess()`: 重启指定进程
  - `ListProcesses()`: 列出所有进程状态
  - `StartMonitor()`: 监控进程状态并自动重启
  - `Run()`: 进程运行逻辑（包含自动重启机制）
  - `Stop()`: 停止进程（优雅终止）

### 3. RPC 服务器 (`daemon/rpc_server.go`)

- **通信协议**:
  - 基于 HTTP/JSON 的简单 RPC 协议
  - 支持的方法: start, stop, restart, list, status

- **请求处理**:
  - 解析客户端请求
  - 调用对应的进程管理方法
  - 返回结果或错误信息

### 4. Web 管理界面 (`daemon/web_ui.go`)

- **功能组件**:
  - 静态文件服务: 提供 CSS/JS 资源
  - 主页模板: 显示进程列表
  - API 端点: 提供进程数据接口

- **用户界面**:
  - 进程列表视图
  - 启动/停止/重启按钮
  - 实时状态更新

### 5. 命令行客户端 (`client/pm2-win-cli.go`)

- **命令支持**:
  - `start`: 启动新进程
  - `stop`: 停止进程
  - `restart`: 重启进程
  - `list`: 列出所有进程

- **参数解析**:
  - 使用 `flag` 包解析命令行参数
  - 验证必要参数
  - 构造 RPC 请求

## 使用示例

### 1. 安装守护进程服务

```powershell
# 编译守护进程
go build -o pm2-win-daemon.exe daemon/main.go

# 安装服务
pm2-win-daemon.exe -install
```

### 2. 启动服务

```powershell
Start-Service -Name PM2WinDaemon
```

### 3. 使用命令行客户端

```powershell
# 编译客户端
go build -o pm2-win-cli.exe client/pm2-win-cli.go

# 启动 Node.js 应用
pm2-win-cli.exe start -id myapp -name "My Node App" -cmd "node" -args "app.js" -dir "C:\myapp" -log "C:\logs\myapp.log"

# 列出所有进程
pm2-win-cli.exe list

# 停止进程
pm2-win-cli.exe stop -id myapp

# 重启进程
pm2-win-cli.exe restart -id myapp
```

### 4. 访问 Web 界面

打开浏览器访问: `http://localhost:8080`

## 生产环境增强建议

1. **安全加固**:
   - 添加 RPC 认证
   - 使用 HTTPS
   - 限制访问 IP

2. **监控集成**:
   - 添加 Prometheus 指标端点
   - 集成 Windows 事件日志
   - 实现健康检查 API

3. **高级功能**:
   - 进程资源限制（CPU/内存）
   - 配置文件管理
   - 日志轮转
   - 集群模式支持

4. **用户界面增强**:
   - 实时日志查看器
   - 性能图表
   - 配置文件编辑器

5. **部署优化**:
   - 制作安装程序
   - 添加自动更新功能
   - 提供系统托盘图标

这个简易的 PM2 式进程守护系统提供了核心的进程管理功能，包括启动、停止、重启、监控和自动重启。通过命令行客户端和 Web 界面，用户可以方便地管理后台进程。系统设计为 Windows 服务运行，确保长期稳定工作，适合在 Windows 服务器上部署各种后台应用和服务。