package av_check

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// 标记
func tagPrint() {
	fmt.Println("\033[31;1m=========================================================\033[0m\033[34;1m")
	fmt.Println("     ___                   __              __  ")
	fmt.Println("    /   |_   __      _____/ /_  ___  _____/ /__")
	fmt.Println("   / /| | | / /_____/ ___/ __ \\/ _ \\/ ___/ //_/")
	fmt.Println("  / ___ | |/ /_____/ /__/ / / /  __/ /__/ ,<  \033[0mversion:\033[34;1m")
	fmt.Printf(" /_/  |_|___/      \\___/_/ /_/\\___/\\___/_/|_| \033[1;33m %8s\033[0m\033[34;1m\n", version)
	fmt.Println("\033[0m\033[31;1m=========================================================\033[0m")
}

// 读取进程
func readProcesses(prostr string) []string {
	// 进行正则匹配
	re, _ := regexp.Compile(`.*?\.(exe|EXE)`)
	// 处理输出的数据
	return re.FindAllString(prostr, -1)
}

// 获取当前系统的进程
func getProcesses() ([]string, error) {
	// 判断命令是否存在
	s, err := exec.LookPath("tasklist")
	// 如果存在就输入
	if err == nil {
		// 创建变量
		var out bytes.Buffer
		// 构造要执行的命令
		cmd := exec.Command(s, "/svc")
		cmd.Stdout = &out
		// 运行
		err := cmd.Run()
		if err != nil {
			return nil, err
		}
		// 处理输出的数据
		return readProcesses(out.String()), nil
	} else {
		return nil, err
	}
}

// 去重
func RemoveDuplicate(old []string) []string {
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// 读取文件并以string形式返回内容
func Readingfile(filename string) ([]string, error) {
	fi, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}
	// 判断文件的大小是否超过限制
	if fi.Size() >= 10485760 {
		return nil, errors.New(filename + " 文件超出限制")
	}
	// 读取文件信息
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return readProcesses(string(content)), nil

}

// 判断字符串是否在列表中
func strinlist(str string, av AvType) {
	for _, s := range av.Processes {
		// 使用strings.EqualFold将两个字符串统一格式化
		if strings.EqualFold(str, s) {
			wg.Add(1)
			result := "防病毒软件: " + av.Name + "\t进程:" + s + "\t官网: " + av.Url
			resultlist <- result
		}
	}
}

// 结构体转换为json
func Switchjson(date []AvType) error {
	jsonByteData, err := json.Marshal(date)
	if err != nil {
		return err
	}
	WriteFile(string(jsonByteData), "demo.json")
	return nil
}

// 文件写入
func WriteFile(result string, filename string) {
	var text = []byte(result + "\n")
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("[\033[31;1m-\033[0m] 打开文件 %s 失败, %v\n", filename, err)
		return
	}
	_, err = f.Write(text)
	f.Close()
	if err != nil {
		fmt.Printf("[\033[31;1m-\033[0m] 写入文件 %s 失败, %v\n", filename, err)
	}
}

// 读取json文件
func Readjsonfile(filename string) ([]AvType, error) {
	// 设置json文件
	var jsonlist []AvType
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &jsonlist)
	if err != nil {
		return nil, err
	}
	return jsonlist, nil
}

// 解析参数
func analysis() {
	flag.StringVar(&outfile, "o", "result.txt", "输出结果文件")
	flag.StringVar(&proce, "p", "", "识别指定进程")
	flag.BoolVar(&localpro, "lp", false, "是否识别本机进程")
	flag.StringVar(&procefile, "pf", "", "识别指定进程文件")
	flag.StringVar(&avfile, "av", "", "自定义的杀软")
	// 解析命令行参数
	flag.Parse()
}
