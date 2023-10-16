package av_check

import (
	"fmt"
	"sync"
	"time"
)

// 存放av特征的数据结构
type AvType struct {
	Name      string   `json:"name"`
	Processes []string `json:"processes"`
	Url       string   `json:"url"`
}

// 声明全局等待组变量
var wg sync.WaitGroup

// 存放结果列表
var resultlist = make(chan string, 10)

// 主函数
func Run() {
	// 输出tag
	tagPrint()
	// 获取当前时间
	currenttime := time.Now()
	// 解析参数
	analysis()
	// 判断是否进行指定进程识别
	if procefile != "" {
		prolist, err := Readingfile(procefile)
		if err != nil {
			fmt.Println("[\033[31;1m-\033[0m] 读取文件失败，原因是：", err)
			return
		}
		processeslist = append(processeslist, prolist...)
	}
	if proce != "" {
		prolist := readProcesses(proce)
		processeslist = append(processeslist, prolist...)
	}
	if localpro {
		prolist, err := getProcesses()
		if err != nil {
			fmt.Println("[\033[31;1m-\033[0m] 获取进程失败，原因是：", err)
			return
		}
		processeslist = append(processeslist, prolist...)
	}
	// 去重
	processeslist = RemoveDuplicate(processeslist)
	if len(processeslist) == 0 {
		fmt.Println("[\033[31;1m-\033[0m] 没有设置需要识别的进程")
		return
	}
	// 判断是否有自定义杀软进程文件
	if avfile != "" {
		avjsonlist, err := Readjsonfile(avfile)
		if err != nil {
			// 写入demo的json信息
			Switchjson(Demo)
			fmt.Println("[\033[31;1m-\033[0m] 自定义杀软文件读取失败！\n请查看 \033[0;38;5;214mdemo.json\033[0m 文件格式，错误信息为：", err, "下面检测使用默认杀软特征库！")
		} else {
			Avdatalist = append(Avdatalist, avjsonlist...)
		}
	}

	// 拼接结果
	outfile = fmt.Sprintf("%d%d%d%s", currenttime.Year(), currenttime.Month(), currenttime.Day(), outfile)
	// 开始扫描
	log := "识别开始！时间为：" + currenttime.Format("2006-01-02 15:04:05")
	WriteFile(log, outfile)
	fmt.Println("[\033[32;1m+\033[0m]", log)
	go func() {
		for av := range resultlist {
			// 写入文件
			WriteFile(av, outfile)
			fmt.Println("[\033[32;1m+\033[0m] \033[0;38;5;214m" + av + "\033[0m")
			wg.Done()
		}
	}()
	// 并发读取杀软信息
	for _, p := range processeslist {
		for _, av := range Avdatalist {
			go strinlist(p, av)
		}
	}
	wg.Wait()
	// 扫描结束
	log = "结束识别！日志文件位置:" + outfile
	WriteFile(log, outfile)
	fmt.Println("[\033[32;1m+\033[0m]", log)
}
