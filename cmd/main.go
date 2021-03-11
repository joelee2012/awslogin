package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/joelee2012/aws-login/pkg/awslogin"
	"github.com/rhysd/abspath"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/go-ini/ini.v1"
)

const defaultConfig  = "~/.aws/config"
const sectionName = "aws-login"
var needKeys = [...]string{"url", "username", "password"}

func readDefaultConfig(file string) (map[string]string, error) {
	absPath, err := abspath.ExpandFrom(file)
	if err != nil {
		return nil, err
	}
	filePath := absPath.String()
	if _, err := os.Stat(filePath); err != nil && os.IsNotExist(err) {
		return nil, err
	}
	ini, err := ini.Load(filePath)
	if err != nil {
		return nil, fmt.Errorf("load %s failed with error: %v", filePath, err)
	}
	sec, err := ini.GetSection(sectionName)
	if err != nil {
		return nil, err
	}
	data := make(map[string]string)
	for _, key := range needKeys {
		keyValue, err := sec.GetKey(key)
		if err != nil {
			continue
		}
		data[key] = keyValue.Value()
	}
	return data, nil
}

func readUserInput(defaultValue map[string]string) map[string]string {
	var data []byte
	for _, e := range needKeys {
		if e == "password" {
			fmt.Print("password: ")
			data, _ = terminal.ReadPassword(int(os.Stdin.Fd()))
		} else {
			fmt.Printf("%s[%s]: ", e, defaultValue[e])
			fmt.Scanln(&data)
		}
		if len(data) != 0 {
			defaultValue[e] = string(data)
		}
	}
	return defaultValue
}


func Run() error {
	config, err := readDefaultConfig(defaultConfig)
	if err != nil {
		return err
	}
	userInput := readUserInput(config)

	awslogin := awslogin.NewClient(userInput["url"],userInput["username"], userInput["password"])
	if err := awslogin.Login(); err != nil {
		return err
	}

	if err := awslogin.ParseResponse(); err != nil {
		return err
	}
	arnRoles, err := awslogin.GetArnRoles()
	if err != nil {
		return err
	}

	fmt.Println("please select role:")
	for index, role := range arnRoles {
		fmt.Printf("[%d]: %s\n", index, strings.Split(role, ",")[1])
	}
	var choice int
	fmt.Scanln(&choice)
	arns := strings.Split(arnRoles[choice], ",")
	cred, err := awslogin.GetSTSCredential(arns[0], arns[1])
	if err != nil {
		return err
	}

	if err := awslogin.WriteCredentialToIni(cred, "my.ini"); err != nil {
		return err
	}
	return nil
}

