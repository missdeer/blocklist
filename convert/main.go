package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	"_":                         "https://raw.githubusercontent.com/missdeer/blocklist/master/blacklist.lst",
}

var (
	// 定义需要被替换的列表项
	replacements      = []string{"||", "^third-party", "^", "$third-party", ",third-party", "$all", ",all", "$image", ",image", ",important", "$script", ",script", "$object", ",object", "$popup", ",popup", "$empty", "$object-subrequest", "$document", "$subdocument", ",subdocument", "$ping", "$important", "$badfilter", ",badfilter", "$websocket", "$cookie", "$other"}
	allDomainsMap     = sync.Map{}
	allDomainCount    = atomic.Int32{}
	allExceptionsMap  = sync.Map{}
	allExceptionCount = atomic.Int32{}
	validPattern      = regexp.MustCompile(`^[a-zA-Z0-9\-_\.]+$`)
)

func isASCII(s string) bool {
	for _, c := range s {
		if c > 127 { // ASCII字符的编码范围是0-127
			return false
		}
	}
	return true
}

func convert(listName string, listUrl string) {
	client := &http.Client{
		Timeout: time.Second * 60,
	}

	fmt.Println("Converting", listName)

	resp, err := client.Get(listUrl)
	if err != nil {
		fmt.Println("error", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("Got", listName)
	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Got", len(body), "bytes")
	lines := strings.Split(string(body), "\n")
	fmt.Println("Splitted to", len(lines), "lines")
	// HOSTS header
	var hosts strings.Builder
	hosts.WriteString(fmt.Sprintf("# %s\n#\n# Converted from %s\n# Updated at %s\n#\n\n", listName, listUrl, time.Now().Format(time.RFC1123)))

	domains := map[string]struct{}{}
	exceptions := map[string]struct{}{}

	for _, filter := range lines {
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

		if strings.Contains(filter, "~") || filter == "" || strings.HasPrefix(filter, ".") || strings.HasSuffix(filter, ".") ||
			strings.HasPrefix(filter, "-") || strings.HasPrefix(filter, "_") || strings.HasPrefix(filter, "!") || strings.HasSuffix(filter, "|") {
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
			allExceptionsMap.Store("0.0.0.0 "+filter[2:], struct{}{})
			allExceptionCount.Add(1)
			continue
		}

		if !validPattern.MatchString(filter) {
			continue
		}

		if utils.InWhitelist(filter) {
			exceptions["0.0.0.0 "+filter] = struct{}{}
			allExceptionsMap.Store("0.0.0.0 "+filter, struct{}{})
			allExceptionCount.Add(1)
			continue
		}

		domains["0.0.0.0 "+filter] = struct{}{}
		allDomainsMap.Store("0.0.0.0 "+filter, struct{}{})
		allDomainCount.Add(1)
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

	if listName != "_" {
		os.WriteFile(listName+".txt", []byte(hosts.String()), 0644)
		fmt.Println(listName, "converted to HOSTS file - see", listName+".txt")
	}
}

func main() {
	var wg sync.WaitGroup
	wg.Add(len(lists))
	for listName, listUrl := range lists {
		go func() {
			convert(listName, listUrl)
			wg.Done()
		}()
	}
	wg.Wait()

	// 创建一个切片来存储 map 的 keys
	allDomains := []string{}
	// convert allDomainsMap to allDomains
	allDomainsMap.Range(func(key, value interface{}) bool {
		domain := key.(string)
		if _, ok := allExceptionsMap.Load(domain); !ok {
			allDomains = append(allDomains, domain[8:])
		}
		return true
	})
	sort.Strings(allDomains)

	fmt.Println("Got", len(allDomains), "domains in total")

	// 写入domains.txt
	writeDomains(allDomains)

	// 写入hosts文件
	writeHosts(allDomains)

	// 写入dnsmasq.conf
	writeDnsmasqConf(allDomains)

	// 写入SmartDNS配置文件
	writeSmartDNSConf(allDomains)

	// 写入Surge配置文件
	writeSurgeConf(allDomains)

	// 写入Surge2配置文件
	writeSurge2Conf(allDomains)
}

// 写入domains.txt
func writeDomains(domains []string) {
	var domainList strings.Builder
	for _, domain := range domains {
		domainList.WriteString(fmt.Sprintf("%s\n", domain))
	}

	os.WriteFile("alldomains.txt", []byte(domainList.String()), 0644)
	fmt.Println("all domains converted to domain list - see alldomains.txt")
}

// 写入hosts文件
func writeHosts(domains []string) {
	var hosts strings.Builder
	hosts.WriteString(fmt.Sprintf("# All domains blocked\n#\n# Converted from Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Updated at %s\n# Total count: %d\n# Update URL: https://raw.githubusercontent.com/missdeer/blocklist/master/convert/hosts\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		hosts.WriteString(fmt.Sprintf("0.0.0.0 %s\n", domain))
	}

	os.WriteFile("hosts", []byte(hosts.String()), 0644)
	fmt.Println("all domains converted to HOSTS file - see hosts")
}

// 写入dnsmasq.conf
func writeDnsmasqConf(domains []string) {
	var dnsmasq strings.Builder
	dnsmasq.WriteString(fmt.Sprintf("# All domains blocked for DNSMasq\n#\n# Converted from Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Updated at %s\n# Total count: %d\n# Update URL: https://raw.githubusercontent.com/missdeer/blocklist/master/convert/dnsmasq.conf\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		dnsmasq.WriteString(fmt.Sprintf("address=/%s/\n", domain))
	}

	os.WriteFile("dnsmasq.conf", []byte(dnsmasq.String()), 0644)
	fmt.Println("all domains converted to dnsmasq.conf - see dnsmasq.conf")
}

// 写入SmartDNS配置文件
func writeSmartDNSConf(domains []string) {
	var smartdns strings.Builder
	smartdns.WriteString(fmt.Sprintf("# All domains blocked for SmartDNS\n#\n# Converted from Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Updated at %s\n# Total count: %d\n# Update URL: https://raw.githubusercontent.com/missdeer/blocklist/master/convert/smartdns.conf\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		smartdns.WriteString("nameserver /" + domain + "/#\n")
	}

	os.WriteFile("smartdns.conf", []byte(smartdns.String()), 0644)
	fmt.Println("all domains converted to SmartDNS file - see smartdns.conf")
}

// 写入Surge配置文件
func writeSurgeConf(domains []string) {
	var surge strings.Builder
	surge.WriteString(fmt.Sprintf("# All domains blocked for Surge\n#\n# Converted from Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Updated at %s\n# Total count: %d\n# Update URL: https://raw.githubusercontent.com/missdeer/blocklist/master/convert/surge.conf\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	for _, domain := range domains {
		surge.WriteString(fmt.Sprintf("DOMAIN-SUFFIX,%s\n", domain))
	}

	os.WriteFile("surge.conf", []byte(surge.String()), 0644)
	fmt.Println("all domains converted to Surge file - see surge.conf")
}

// 写入Surge2配置文件
func writeSurge2Conf(domains []string) {
	var surge2 strings.Builder
	surge2.WriteString(fmt.Sprintf("# All domains blocked for Surge2\n#\n# Converted from Anti-Ad/AdGuard/EasyPrivacy/DD-AD\n# Updated at %s\n# Total count: %d\n# Update URL: https://raw.githubusercontent.com/missdeer/blocklist/master/convert/surge2.conf\n#\n\n", time.Now().Format(time.RFC1123), len(domains)))

	surge2.WriteString("#DOMAIN-SET,https://raw.githubusercontent.com/missdeer/blocklist/master/convert/surge2.conf,REJECT\n")
	for _, domain := range domains {
		surge2.WriteString(fmt.Sprintf(".%s/\n", domain))
	}

	os.WriteFile("surge2.conf", []byte(surge2.String()), 0644)
	fmt.Println("all domains converted to Surge2 file - see surge2.conf")
}
