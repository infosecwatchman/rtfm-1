package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func main() {
	tags := []string{"linux","bash","text manipulation","cisco","networking","loop","pivoting","files","passwords","enumeration","user information","interesting","scanning","hp","brute","http","web application","XSS","cookies","metasploit","certificates","stealth","smb","MitM","dns","package management","reverse shells","Windows","perl","python","php","ruby","sql injection","mysql","shell","mssql","Oracle","users","wireless","wifi","configuration","av evasion","powershell","memory","impacket","filesystem","IIS","process management","privilege escalation","remote command shell","hashes","recon","cracking","nessus","subnets","packet capture","reference","web address","java","solaris","forensics","ldap","Anti Virus","GIT","interesting","Cloud","RDP","shells","encryption","Troll","buffer overflow","mona","interseting","brute force","Apple","encoding","ascii","web app","Cyber Essentials","tools","code execution","jsp","nfs","fileshare","database","ipv6","snmp","shellshock","curl","Groovy"}
	for _, tag := range tags {
		var docBlob []string
		markdownDoc, err := os.Create(fmt.Sprintf("./output/%s.md", tag))
		if err != nil {
			log.Fatal(err)
		}
		defer markdownDoc.Close()
		//tag = fmt.Sprintf(`'%s'`, tag)
		//tag = "user information"
		fmt.Println(tag)
		command := fmt.Sprintf("python3 ./rtfm.py -t %s", tag)
		cmd := exec.Command("cmd", "/C", command)
		fmt.Println(cmd.Args)
		out, err := cmd.CombinedOutput()
		fmt.Println(string(out))

		if err != nil {
			println(err.Error())
			return
		}

		//fmt.Println(string(out))
		regex, _ := regexp.Compile(`\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+([\s\S]*?)\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+\+`)
		entries := regex.FindAll(out, -1)
		for entrynum, entry := range entries {
			regex2, err := regexp.Compile(`.*?: `)
			if err != nil {
				fmt.Println(err)
				return
			}
			//Command
			regex1, _ := regexp.Compile(`Command\x20+:(.*)`)
			Command := regex1.FindString(string(entry))
			RemoveCommand := regex2.FindString(Command)
			Command = strings.ReplaceAll(Command, RemoveCommand, "")

			//Comment
			regex1, _ = regexp.Compile(`Comment\x20+:(.*)`)
			Comment := regex1.FindString(string(entry))
			RemoveComment := regex2.FindString(Comment)
			Comment = strings.ReplaceAll(Comment, RemoveComment, "")

			//Tags
			regex1, _ = regexp.Compile(`Tags\x20+:(.*)`)
			Tags := regex1.FindString(string(entry))
			RemoveTags := regex2.FindString(Tags)
			Tags = strings.ReplaceAll(Tags, RemoveTags, "")
			Tags = strings.TrimSpace(Tags)

			//References
			regex1, _ = regexp.Compile(`(References)([\s\S]*)`)
			References := regex1.FindString(string(entry))
			References = strings.ReplaceAll(References, "++++++++++++++++++++++++++++++", "")
			References = strings.ReplaceAll(References, "__________", "")
			References = strings.ReplaceAll(References, "References", "")

			entrynum = entrynum + 1
			text := fmt.Sprintf("### %d. %s\n```\n%s\n```\n**- %s**\n#### References:%s__________\n", entrynum, Comment, Command, Tags, References)
			docBlob = append(docBlob, text)
		}
		for _, line := range docBlob {
			_, err := markdownDoc.WriteString(line)
			if err != nil {
				log.Fatal(err)
			}
		}

	}

}
