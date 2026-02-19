package utils

import (
	"regexp"
	"strings"
)

var (
	whitelist = []whitelistChecker{
		equal(`img.particlenews.com`),
		equal(`amazonaws.com`),
		equal(`mp.weixin.qq.com`),
		equal(`url.cn`),
		equal(`scootersoftware.com`),
		equal(`qq.com`),
		equal(`www.qq.com`),
		equal(`analytics.163.com`),
		equal(`163.com`),
		equal(`behance.net`),
		equal(`soundcloud.com`),
		equal(`global.ssl.fastly.net`),
		suffix(`gyrovague.com`),
		suffix(`msedge.net`),
		suffix(`internetdownloadmanager.com`),
		suffix(`.alcohol-soft.com`),
		suffix(`.googlevideo.com`),
		suffix(`.in-addr.arpa`),
		suffix(`.url.cn`),
		suffix(`.verisign.com`),
		suffix(`bitcanna.io`),
		suffix(`jsdelivr.net`),
		suffix(`.jpg`),
		suffix(`.gif`),
		suffix(`uptain.de`),
		contains(`xmlhttprequest`),
		contains(`google-analytics`),
		contains(`mozilla`),
		contains(`alibaba`),
		contains(`alidns`),
		contains(`alicdn`),
		contains(`alipay`),
		contains(`tbcache`),
		contains(`taobao`),
		contains(`hzshudian`),
		regex(`^s3[\d\w\-]*.amazonaws.com`),
		regex(`^[^\.]+\.elb\.amazonaws\.com`),
		regex(`[^ad]\.mail\.ru`),
		regex(`[^ad]\.daum\.net`),
		regex(`^\w{1,10}\.yandex\.`),
	}
)

func InWhitelist(domain string) bool {
	for _, wl := range whitelist {
		if wl(domain) {
			return true
		}
	}
	return false
}

type whitelistChecker func(s string) bool

func contains(pattern string) whitelistChecker {
	return func(s string) bool {
		return strings.Contains(s, pattern)
	}
}

func suffix(pattern string) whitelistChecker {
	return func(s string) bool {
		return strings.HasSuffix(s, pattern)
	}
}

func prefix(pattern string) whitelistChecker {
	return func(s string) bool {
		return strings.HasPrefix(s, pattern)
	}
}

func equal(pattern string) whitelistChecker {
	return func(s string) bool {
		return pattern == s
	}
}

func regex(pattern string) whitelistChecker {
	r := regexp.MustCompile(pattern)
	return func(s string) bool {
		return r.MatchString(s)
	}
}
