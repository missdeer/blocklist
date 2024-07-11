package utils

import (
	"regexp"
	"strings"
)

var (
	whitelist = []whitelistChecker{
		equal(`img.particlenews.com`),
		contains(`google-analytics`),
		suffix(`msedge.net`),
		equal(`amazonaws.com`),
		equal(`mp.weixin.qq.com`),
		equal(`url.cn`),
		regex(`^s3[\d\w\-]*.amazonaws.com`),
		suffix(`internetdownloadmanager.com`),
		suffix(`.alcohol-soft.com`),
		equal(`scootersoftware.com`),
		regex(`[^ad]\.mail\.ru`),
		regex(`[^ad]\.daum\.net`),
		regex(`^\w{1,10}\.yandex\.`),
		suffix(`.googlevideo.com`),
		regex(`^[^\.]+\.elb\.amazonaws\.com`),
		suffix(`.in-addr.arpa`),
		suffix(`.url.cn`),
		equal(`qq.com`),
		equal(`www.qq.com`),
		equal(`analytics.163.com`),
		equal(`163.com`),
		equal(`behance.net`),
		suffix(`.verisign.com`),
		contains(`mozilla`),
		suffix(`bitcanna.io`),
		suffix(`jsdelivr.net`),
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
