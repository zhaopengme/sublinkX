package node

import (
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
)

// ss匹配规则
type Ss struct {
	Param      Param
	Server     string
	Port       int
	Name       string
	Type       string
	Plugin     string
	PluginOpts map[string]interface{}
}
type Param struct {
	Cipher   string
	Password string
}

func parsingSS(s string) (string, string, string, string) {
	/* ss url编码分为三部分：加密方式、服务器地址和端口、备注
	://和@之前为第一部分 @到#之间为第二部分 #之后为第三部分
	第一部分 为加密方式和密码，格式为：加密方式:密码	示例：aes-128-gcm:123456
	第二部分 为服务器地址和端口，格式为：服务器地址:端口	示例：xxx.xxx:12345
	第三部分 为备注，格式为：#备注	示例：#备注
	第四部分 为插件参数，格式为：?plugin=xxx;xxx=xxx	示例：?plugin=v2ray-plugin;mode=tls
	*/
	u, err := url.Parse(s)
	if err != nil {
		log.Println("ss url parse fail.", err)
		return "", "", "", ""
	}
	if u.Scheme != "ss" {
		log.Println("ss url parse fail, not ss url.")
		return "", "", "", ""
	}
	// 处理url全编码的情况
	if u.User == nil {
		// 截取ss://后的字符串
		raw := s[5:]
		s = "ss://" + Base64Decode(raw)
		u, err = url.Parse(s)
	}
	var auth, addr, name, query string
	auth = u.User.String()
	if u.Host != "" {
		addr = u.Host
	}
	if u.Fragment != "" {
		name = u.Fragment
	}
	// 获取原始query参数
	if u.RawQuery != "" {
		query = u.RawQuery
	}
	return auth, addr, name, query
}

// 开发者测试
func CallSSURL() {
	ss := Ss{}
	// ss.Name = "测试"
	ss.Server = "baidu.com"
	ss.Port = 443
	ss.Param.Cipher = "2022-blake3-aes-256-gcm"
	ss.Param.Password = "asdasd"
	fmt.Println(EncodeSSURL(ss))
}

// ss 编码输出
func EncodeSSURL(s Ss) string {
	//编码格式 ss://base64(base64(method:password)@hostname:port)
	p := Base64Encode(s.Param.Cipher + ":" + s.Param.Password)
	// 假设备注没有使用服务器加端口命名
	if s.Name == "" {
		s.Name = s.Server + ":" + strconv.Itoa(s.Port)
	}
	param := fmt.Sprintf("%s@%s:%s#%s",
		p,
		s.Server,
		strconv.Itoa(s.Port),
		s.Name,
	)
	return "ss://" + param
}

func DecodeSSURL(s string) (Ss, error) {
	// 解析ss链接
	param, addr, name, query := parsingSS(s)
	// base64解码
	param = Base64Decode(param)
	// 判断是否为空
	if param == "" || addr == "" {
		return Ss{}, fmt.Errorf("invalid SS URL")
	}
	// 解析参数
	parts := strings.Split(addr, ":")
	port, _ := strconv.Atoi(parts[len(parts)-1])
	server := strings.Replace(ValRetIPv6Addr(addr), ":"+parts[len(parts)-1], "", -1)
	cipher := strings.Split(param, ":")[0]
	password := strings.Replace(param, cipher+":", "", 1)
	// 如果没有备注则使用服务器加端口命名
	if name == "" {
		name = addr
	}

	// 解析plugin参数
	var plugin string
	pluginOpts := make(map[string]interface{})
	if query != "" {
		// plugin参数格式: plugin=v2ray-plugin;mode=tls;tls=true;host=xxx
		// 分号分隔各个参数
		queryParts := strings.Split(query, ";")
		for _, part := range queryParts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := kv[0]
			value := kv[1]
			if key == "plugin" {
				plugin = value
			} else {
				// 处理 tls=true/false 转换为 bool
				if value == "true" {
					pluginOpts[key] = true
				} else if value == "false" {
					pluginOpts[key] = false
				} else {
					pluginOpts[key] = value
				}
			}
		}
	}

	// 开发环境输出结果
	if CheckEnvironment() {
		fmt.Println("Param:", Base64Decode(param))
		fmt.Println("Server", server)
		fmt.Println("Port", port)
		fmt.Println("Name:", name)
		fmt.Println("Cipher:", cipher)
		fmt.Println("Password:", password)
		fmt.Println("Plugin:", plugin)
		fmt.Println("PluginOpts:", pluginOpts)
	}
	// 返回结果
	return Ss{
		Param: Param{
			Cipher:   cipher,
			Password: password,
		},
		Server:     server,
		Port:       port,
		Name:       name,
		Type:       "ss",
		Plugin:     plugin,
		PluginOpts: pluginOpts,
	}, nil
}
