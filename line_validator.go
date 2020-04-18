package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

type lineValidator func(s string) string

func hostLine(addr string) lineValidator {
	regexPattern := fmt.Sprintf(`^(%s)\s+([\w\d\-\._]+)`, strings.Replace(addr, `.`, `\.`, -1))
	validDomain := regexp.MustCompile(`^((xn--)?[\w\d]+([\w\d\-_]+)*\.)+\w{2,}$`)
	validLine := regexp.MustCompile(regexPattern)
	return func(s string) string {
		ss := validLine.FindStringSubmatch(s)
		if len(ss) > 1 {
			if validDomain.MatchString(ss[2]) {
				return ss[2]
			}
		}
		log.Println("invalid line:", s)
		return ""
	}
}

func domainListLine() lineValidator {
	validDomain := regexp.MustCompile(`^((xn--)?[\w\d]+([\w\d\-_]+)*\.)+\w{2,}$`)
	return func(s string) string {
		if validDomain.MatchString(s) {
			return s
		}
		log.Println("invalid domain:", s)
		return ""
	}
}
