package file

import (
	"os"
)

// 判断日志文件是否存在
func LogFileExists(path string, name string) *os.File {
	var filePath string = path
	if filePath != "" {
		logFile, _ := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		logFile.Close()
		return logFile
	} else {
		filePath = "/log/" + name + ".log"
		logFile, _ := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		logFile.Close()
		return logFile
	}
}
