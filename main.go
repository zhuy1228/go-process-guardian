package main

import (
	"flag"
	"fmt"
	"os"
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
}
