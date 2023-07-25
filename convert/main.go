package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
	"net"
	"golang.org/x/net/idna"
)

// 定义一个映射存储列表名称和链接
var lists = map[string]string{
	"AdguardMobileAds":           "https://cdn.jsdelivr.net/gh/AdguardTeam/FiltersRegistry@master/filters/filter_11_Mobile/filter.txt",
	"AdguardMobileSpyware":       "https://cdn.jsdelivr.net/gh/AdguardTeam/AdguardFilters@master/SpywareFilter/sections/mobile.txt",
	"AdguardDNS":                 "https://cdn.jsdelivr.net/gh/AdguardTeam/AdGuardSDNSFilter@gh-pages/Filters/filter.txt",
	"AdguardCNAMEAds":            "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_ads.txt",
	"AdguardCNAMEClickthroughs":  "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_clickthroughs.txt",
	"AdguardCNAMEMicrosites":     "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_microsites.txt",
	"AdguardCNAME":               "https://cdn.jsdelivr.net/gh/AdguardTeam/cname-trackers@master/data/combined_disguised_trackers.txt",
	"AdguardTracking":            "https://cdn.jsdelivr.net/gh/AdguardTeam/FiltersRegistry@master/filters/filter_3_Spyware/filter.txt",
	"EasyPrivacySpecific":        "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_specific.txt",
	"EasyPrivacy3rdParty":        "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_thirdparty.txt",
	"EasyPrivacyCNAME":           "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easyprivacy/easyprivacy_specific_cname.txt",
}

// 定义需要被替换的列表项
var replacements = []string{"||", "^third-party", "^", "$third-party", ",third-party", "$all", ",all", "$image", ",image", ",important", "$script", ",script", "$object", ",object", "$popup", ",popup", "$empty", "$object-subrequest", "$document", "$subdocument", ",subdocument", "$ping", "$important", "$badfilter", ",badfilter", "$websocket", "$cookie", "$other"}

func main() {
	client := &http.Client{
		Timeout: time.Second * 60,
	}
	for name, list := range lists {
		fmt.Println("Converting", name)

		resp, err := client.Get(list)
		if err != nil {
			fmt.Println("error", err)
			continue
		}
		defer resp.Body.Close()
		fmt.Println("Got", name)
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("Got", len(body), "bytes")
		lines := strings.Split(string(body), "\n")
		fmt.Println("Splitted to", len(lines), "lines")
		// HOSTS header
		var hosts strings.Builder
		hosts.WriteString(fmt.Sprintf("# %s\n#\n# Converted from - %s\n# Last converted - %s\n#\n\n", name, list, time.Now().Format(time.RFC1123)))

		domains := map[string]bool{}
		exceptions := map[string]bool{}

		for _, filter := range lines {
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

			if _, err := net.LookupIP(filter); err != nil {
				if ascii, err := idna.ToASCII(filter); err == nil {
					filter = ascii
				}
			}

			if strings.HasPrefix(filter, "@@") {
				exceptions["0.0.0.0 "+filter[2:]] = true
				continue
			}

			domains["0.0.0.0 "+filter] = true
		}

		for domain := range domains {
			if _, ok := exceptions[domain]; !ok {
				hosts.WriteString(domain + "\n")
			}
		}

		ioutil.WriteFile(name+".txt", []byte(hosts.String()), 0644)
		fmt.Println(name, "converted to HOSTS file - see", name+".txt")
	}
}
