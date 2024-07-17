package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/missdeer/blocklist/utils"
	"golang.org/x/net/idna"
)

// 定义一个映射存储列表名称和链接
var lists = map[string]string{
	"Anti-Ad":                   "https://anti-ad.net/domains.txt",
	"AdguardMobileAds":          "https://cdn.jsdelivr.net/gh/AdguardTeam/FiltersRegistry@master/filters/filter_11_Mobile/filter.txt",
	"AdguardMobileSpyware":      "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SpywareFilter/sections/mobile.txt",
	"AdguardDNS":                "https://cdn.jsdelivr.net/gh/AdguardTeam/AdGuardSDNSFilter@gh-pages/Filters/filter.txt",
	"AdguardCNAMEAds":           "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_ads.txt",
	"AdguardCNAMEClickthroughs": "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_clickthroughs.txt",
	"AdguardCNAMEMicrosites":    "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_microsites.txt",
	"AdguardCNAME":              "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_trackers.txt",
	"AdguardTracking":           "https://cdn.jsdelivr.net/gh/AdguardTeam/FiltersRegistry@master/filters/filter_3_Spyware/filter.txt",
	"EasyPrivacySpecific":       "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_specific.txt",
	"EasyPrivacy3rdParty":       "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_thirdparty.txt",
	"EasyPrivacyCNAME":          "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_specific_cname.txt",
	"YoutubeAds":                "https://raw.githubusercontent.com/kboghdady/youTube_ads_4_pi-hole/master/youtubelist.txt",
	"DD-AD":                     "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt",
}

// 定义需要被替换的列表项
var replacements = []string{"||", "^third-party", "^", "$third-party", ",third-party", "$all", ",all", "$image", ",image", ",important", "$script", ",script", "$object", ",object", "$popup", ",popup", "$empty", "$object-subrequest", "$document", "$subdocument", ",subdocument", "$ping", "$important", "$badfilter", ",badfilter", "$websocket", "$cookie", "$other"}

func isASCII(s string) bool {
	for _, c := range s {
		if c > 127 { // ASCII字符的编码范围是0-127
			return false
		}
	}
	return true
}

func main() {
	client := &http.Client{
		Timeout: time.Second * 60,
	}
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9\-_\.]+$`)
	alldomains := map[string]struct{}{}
	allexceptions := map[string]struct{}{}
	for name, list := range lists {
		fmt.Println("Converting", name)

		resp, err := client.Get(list)
		if err != nil {
			fmt.Println("error", err)
			continue
		}
		defer resp.Body.Close()
		fmt.Println("Got", name)
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("Got", len(body), "bytes")
		lines := strings.Split(string(body), "\n")
		fmt.Println("Splitted to", len(lines), "lines")
		// HOSTS header
		var hosts strings.Builder
		hosts.WriteString(fmt.Sprintf("# %s\n#\n# Converted from - %s\n# Last converted - %s\n#\n\n", name, list, time.Now().Format(time.RFC1123)))

		domains := map[string]struct{}{}
		exceptions := map[string]struct{}{}

		for index, filter := range lines {
			fmt.Printf("Process %d/%d lines\n", index, len(lines))
			filter = strings.Replace(filter, "\r", "", -1)
			filter = strings.Replace(filter, "\n", "", -1)

			if !strings.Contains(filter, ".") ||
				strings.Contains(filter, "*") ||
				strings.Contains(filter, "/") ||
				strings.Contains(filter, "#") ||
				strings.Contains(filter, " ") ||
				strings.Contains(filter, "abp?") ||
				strings.Contains(filter, "$$") ||
				strings.Contains(filter, "$@$") {
				continue
			}

			if strings.Contains(filter, "$domain") && !strings.Contains(filter, "@@") {
				filter = filter[:strings.Index(filter, "$domain")]
			} else if strings.Contains(filter, "=") {
				continue
			}

			for _, replacement := range replacements {
				filter = strings.ReplaceAll(filter, replacement, "")
			}

			if "soundcloud.com" == filter || "global.ssl.fastly.net" == filter || strings.Contains(filter, "xmlhttprequest") ||
				strings.Contains(filter, "~") || filter == "" || strings.HasPrefix(filter, ".") || strings.HasSuffix(filter, ".") ||
				strings.HasPrefix(filter, "-") || strings.HasPrefix(filter, "_") || strings.HasPrefix(filter, "!") || strings.HasSuffix(filter, "|") ||
				strings.HasSuffix(filter, ".jpg") || strings.HasSuffix(filter, ".gif") {
				continue
			}

			if strings.Contains(filter, ":") {
				filter = filter[:strings.Index(filter, ":")]
			}

			if !isASCII(filter) {
				if ascii, err := idna.ToASCII(filter); err == nil {
					filter = ascii
				}
			}

			if strings.HasPrefix(filter, "@@") {
				exceptions["0.0.0.0 "+filter[2:]] = struct{}{}
				allexceptions["0.0.0.0 "+filter[2:]] = struct{}{}
				continue
			}

			if !validPattern.MatchString(filter) {
				continue
			}

			if utils.InWhitelist(filter) {
				exceptions["0.0.0.0 "+filter] = struct{}{}
				allexceptions["0.0.0.0 "+filter] = struct{}{}
				continue
			}

			domains["0.0.0.0 "+filter] = struct{}{}
			alldomains["0.0.0.0 "+filter] = struct{}{}
		}
		fmt.Printf("\n")
		fmt.Println("Got", len(domains), "domains, except", len(exceptions), "ones")

		// 创建一个切片来存储 map 的 keys
		keys := make([]string, 0, len(domains))
		for k := range domains {
			keys = append(keys, k)
		}

		// 使用 sort 包对切片进行排序
		sort.Strings(keys)

		for _, domain := range keys {
			if _, ok := exceptions[domain]; !ok {
				hosts.WriteString(domain + "\n")
			}
		}

		os.WriteFile(name+".txt", []byte(hosts.String()), 0644)
		fmt.Println(name, "converted to HOSTS file - see", name+".txt")
	}
	// 创建一个切片来存储 map 的 keys
	keys := make([]string, 0, len(alldomains))
	for k := range alldomains {
		keys = append(keys, k)
	}

	// 使用 sort 包对切片进行排序
	sort.Strings(keys)

	sortedDomains := []string{}
	for _, domain := range keys {
		if _, ok := allexceptions[domain]; !ok {
			sortedDomains = append(sortedDomains, domain[8:])
		}
	}

	// 写入hosts文件
	writeHosts(sortedDomains)

	// 写入dnsmasq.conf
	writeDnsmasqConf(sortedDomains)

	// 写入SmartDNS配置文件
	writeSmartDNSConf(sortedDomains)

	// 写入Surge配置文件
	writeSurgeConf(sortedDomains)

	// 写入Surge2配置文件
	writeSurge2Conf(sortedDomains)
}

// 写入hosts文件
func writeHosts(domains []string) {
	var hosts strings.Builder
	hosts.WriteString(fmt.Sprintf("# All domains\n#\n# Converted from - Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Last converted - %s\n# Total count: %d\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		hosts.WriteString(fmt.Sprintf("0.0.0.0 %s\n", domain))
	}

	os.WriteFile("hosts", []byte(hosts.String()), 0644)
	fmt.Println("all domains converted to HOSTS file - see hosts")
}

// 写入dnsmasq.conf
func writeDnsmasqConf(domains []string) {
	var dnsmasq strings.Builder
	dnsmasq.WriteString(fmt.Sprintf("# All domains\n#\n# Converted from - Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Last converted - %s\n# Total count: %d\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		dnsmasq.WriteString(fmt.Sprintf("address=/%s/\n", domain))
	}

	os.WriteFile("dnsmasq.conf", []byte(dnsmasq.String()), 0644)
	fmt.Println("all domains converted to dnsmasq.conf - see dnsmasq.conf")
}

// 写入SmartDNS配置文件
func writeSmartDNSConf(domains []string) {
	var smartdns strings.Builder
	smartdns.WriteString(fmt.Sprintf("# All domains\n#\n# Converted from - Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Last converted - %s\n# Total count: %d\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		smartdns.WriteString("nameserver /" + domain + "/#\n")
	}

	os.WriteFile("smartdns.conf", []byte(smartdns.String()), 0644)
	fmt.Println("all domains converted to SmartDNS file - see smartdns.conf")
}

// 写入Surge配置文件
func writeSurgeConf(domains []string) {
	var surge strings.Builder
	surge.WriteString(fmt.Sprintf("# All domains\n#\n# Converted from - Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Last converted - %s\n# Total count: %d\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		surge.WriteString(fmt.Sprintf("DOMAIN-SUFFIX,%s\n", domain))
	}

	os.WriteFile("surge.conf", []byte(surge.String()), 0644)
	fmt.Println("all domains converted to Surge file - see surge.conf")
}

// 写入Surge2配置文件
func writeSurge2Conf(domains []string) {
	var surge2 strings.Builder
	surge2.WriteString(fmt.Sprintf("# All domains\n#\n# Converted from - Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Last converted - %s\n# Total count: %d\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	surge2.WriteString("#DOMAIN-SET,https://raw.githubusercontent.com/missdeer/blocklist/master/convert/surge2.conf,REJECT\n")
	for _, domain := range domains {
		surge2.WriteString(fmt.Sprintf(".%s/\n", domain))
	}

	os.WriteFile("surge2.conf", []byte(surge2.String()), 0644)
	fmt.Println("all domains converted to Surge2 file - see surge2.conf")
}
