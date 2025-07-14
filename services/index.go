package services

import (
	"go-process-guardian/config"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// 服务管理 注册Windows服务 卸载服务

func InstallService() {
	appConfig, _ := config.LoadConfig()

	// 连接系统的服务管理
	serviceMessage, err := mgr.Connect()
	if err != nil {
		log.Println("连接电脑服务失败，请使用管理员权限运行")
		return
	}
	defer serviceMessage.Disconnect()
	// 打开服务 如果打开失败则创建服务
	service, err := serviceMessage.OpenService(appConfig.ServiceName)
	if err != nil {
		// 若错误码为 ERROR_SERVICE_DOES_NOT_EXIST，表示服务不存在
		if errCode, ok := err.(windows.Errno); ok && errCode == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			createService(serviceMessage)
		}
	}
	if service != nil {
		defer service.Close()
	}
}

func createService(serviceMessage *mgr.Mgr) {
	exePath, err := filepath.Abs(os.Args[0])
	if err != nil {
		log.Fatal(err)
	}
	// 创建服务
	mgrConfig := mgr.Config{
		DisplayName: "PMG Windows",
		Description: "进程守护",
		StartType:   mgr.StartAutomatic,
	}
	appConfig, _ := config.LoadConfig()
	service, err := serviceMessage.CreateService(appConfig.ServiceName, exePath, mgrConfig)
	if err != nil {
		log.Fatal("CreateService failed:", err)
	}
	defer service.Close()
	// 设置恢复策略
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 120 * time.Second},
		{Type: mgr.NoAction},
	}

	if err := service.SetRecoveryActions(recoveryActions, 86400); err != nil {
		log.Println("Warning: failed to set recovery actions:", err)
	}
	// 创建事件日志源
	if err := eventlog.InstallAsEventCreate(appConfig.ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		log.Println("Warning: failed to create event source:", err)
	}

	log.Println("Service installed successfully")
}

func UninstallService() {
	appConfig, _ := config.LoadConfig()
	// 连接系统的服务管理
	serviceMessage, err := mgr.Connect()
	if err != nil {
		log.Println("连接电脑服务失败")
		log.Println(err)
		return
	}
	defer serviceMessage.Disconnect()
	// 打开服务
	service, err := serviceMessage.OpenService(appConfig.ServiceName)
	if err != nil {
		log.Fatal("Service not installed:", err)
		return
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
	if err := eventlog.Remove(appConfig.ServiceName); err != nil {
		log.Println("Warning: failed to remove event source:", err)
	}

	log.Println("Service uninstalled successfully")
}
