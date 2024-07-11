package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
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
	"DD-AD":                     "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/hosts.txt",
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
			fmt.Printf("Process %d/%d lines\r", index, len(lines))
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

			if strings.HasPrefix(filter, "@@") || utils.InWhitelist(filter[2:]) {
				exceptions["0.0.0.0 "+filter[2:]] = struct{}{}
				allexceptions["0.0.0.0 "+filter[2:]] = struct{}{}
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

	var hosts strings.Builder
	hosts.WriteString(fmt.Sprintf("# All domains\n#\n# Converted from - Anti-Ad/AdGuard/EasyPrivacy\n# Last converted - %s\n#\n\n", time.Now().Format(time.RFC1123)))

	for _, domain := range keys {
		if _, ok := allexceptions[domain]; !ok {
			hosts.WriteString(domain + "\n")
		}
	}

	os.WriteFile("alldomains.txt", []byte(hosts.String()), 0644)
	fmt.Println("all domains converted to HOSTS file - see alldomains.txt")
}
