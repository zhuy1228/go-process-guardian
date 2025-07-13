package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
)

var (
	v       = flag.Bool("v", false, "查看版本")
	start   = flag.String("start", "", "启动文件地址")
	name    = flag.String("name", "", "名称")
	restart = flag.String("restart", "", "重启")
	stop    = flag.String("stop", "", "停止")
)

func main() {
	flag.Parse()
	// 获取当前进程信息
	fmt.Println(os.Getpid())
	fmt.Println(os.Getppid())
	if *v {
		fmt.Println("1.0.1")
	}
	if *start != "" {
		fmt.Println("启动：", *start)
	}
	if *name != "" {
		fmt.Println("名称：", *name)
	}
	if *restart != "" {
		fmt.Println("重启：", *restart)
	}
	if *stop != "" {
		fmt.Println("停止：", *stop)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", "src\\index.go")
	cmd.Dir = "D:\\project\\Go\\src\\go-fingerprint\\"
	// if err := cmd.Start(); err != nil {
	// 	fmt.Println("运行报错")
	// }
	// 创建管道捕获标准输出
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Errorf("创建标准输出管道失败: %v", err)
	}

	// 创建管道捕获标准错误
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Errorf("创建标准错误管道失败: %v", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		fmt.Errorf("启动命令失败: %v", err)
	}
	// 使用 WaitGroup 等待输出处理完成
	var wg sync.WaitGroup
	wg.Add(2)

	// 处理标准输出
	go func() {
		defer wg.Done()
		scanAndCapture(stdout, "STDOUT")
	}()

	// 处理标准错误
	go func() {
		defer wg.Done()
		scanAndCapture(stderr, "STDERR")
	}()
	// 等待命令执行完成
	if err := cmd.Wait(); err != nil {
		fmt.Errorf("命令执行失败: %v", err)
	}
	setupSignalHandler()
	// 等待所有输出处理完成
	wg.Wait()
	cmd.Wait()
}

// 扫描并捕获输出
func scanAndCapture(reader io.Reader, prefix string) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		var outputLines []string
		// 捕获输出行（最多保留1000行）
		outputLines = append(outputLines, line)
		if len(outputLines) > 1000 {
			outputLines = outputLines[1:]
		}

		// 实时显示
		fmt.Printf("[%s] %s\n", prefix, line)
	}
}

func setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n接收到中断信号，停止子进程...")
		os.Exit(0)
	}()
}
