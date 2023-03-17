package main

import (
	"bytes"
	"encoding/json"
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
	fmt.Println("\033[31;1m====================================================\033[0m\033[34;1m")
	fmt.Println("        ______  ____\033[31;1m_\033[0m\033[34;1m__\033[31;1m___\033[0m\033[34;1m____\033[31;1m___")
	fmt.Println("       /\033[0m\033[34;1m      ||   。      \033[33;1m。\033[0m\033[34;1m   /")
	fmt.Println("      /  _    \033[31;1m|\033[0m\033[34;1m|____\033[31;1m__\033[0m\033[34;1m_    _  _/ T00ls:")
	fmt.Println("     \033[31;1m/\033[0m\033[34;1m  \033[31;1m/ |\033[0m\033[34;1m   |       /   /\033[31;1m( )\033[0m\033[34;1m   杀软识别工具")
	fmt.Println("    /  \033[31;1m/_\033[0m\033[34;1m_|   |      \033[31;1m/\033[0m\033[34;1m   /   ( )       ")
	fmt.Println("   /  ____    \033[31;1m|\033[0m\033[34;1m  \033[35;1m<-—+—+—+--}\033[0m\033[34;1m\033[31;1m( )\033[0m\033[34;1m____\033[31;1m/|\033[0m\033[34;1m")
	fmt.Println("  \033[31;1m/\033[0m\033[34;1m  /    |   |    /   /    ( \033[33;1m.\033[0m\033[34;1m   . \033[31;1m)\033[0m\033[34;1m")
	fmt.Println(" /\033[31;1m_\033[0m\033[34;1m_/     |_\033[31;1m__|\033[0m\033[34;1m   \033[31;1m/_\033[0m\033[34;1m__/     (\033[31;1m__\033[0m\033[34;1m__=___)  \033[31;1m❤\033[0m")
	fmt.Println("\033[0m\033[31;1m====================================================\033[0m")
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
		// 进行正则匹配
		re, _ := regexp.Compile(`.*?\.(exe|EXE)`)
		// 处理输出的数据
		return RemoveDuplicate(re.FindAllString(out.String(), -1)), nil
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

// 结构体转换为json，并写入文件
func Switchjson(date []AvType) error {
	jsonByteData, err := json.Marshal(date)
	if err != nil {
		return err
	}
	WriteFile(string(jsonByteData), "demo.json")
	return nil
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
	flag.StringVar(&avfile, "av", "", "自定义的杀软进程")
	// 解析命令行参数
	flag.Parse()
}
