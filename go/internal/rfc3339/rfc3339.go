// SPDX-License-Identifier: BSD-3-Clause

// Package rfc3339 reads the dates the Evidence Result and dataset gates
// share: an RFC 3339 date-time with an offset, as a UTC calendar day, and a
// YYYY-MM-DD calendar day.
package rfc3339

import (
	"regexp"
	"strconv"
	"time"
)

// rfc3339WithOffset is RFC 3339 section 5.6 with a required offset, the
// grammar the Python reference (RFC3339_WITH_OFFSET) and the TypeScript
// reader (ts/src/result-root.ts utcDateOf) apply. A leap second is refused.
var (
	rfc3339WithOffset   = regexp.MustCompile(`\A([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(?:[Zz]|([+-])([0-9]{2}):([0-9]{2}))\z`)
	calendarDatePattern = regexp.MustCompile(`\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z`)
)

// Day is a calendar date as yyyymmdd, so dates compare as integers.
type Day int

func validDate(year, month, dayOfMonth int) bool {
	if year < 1 || year > 9999 || month < 1 || month > 12 || dayOfMonth < 1 {
		return false
	}
	return time.Date(year, time.Month(month), dayOfMonth, 0, 0, 0, 0, time.UTC).Day() == dayOfMonth
}

func atoi(parts []string) []int {
	out := make([]int, len(parts))
	for i, part := range parts {
		out[i], _ = strconv.Atoi(part)
	}
	return out
}

// CalendarDate reads a YYYY-MM-DD value: a date that exists, in years
// 0001 to 9999.
func CalendarDate(value string) (Day, bool) {
	match := calendarDatePattern.FindStringSubmatch(value)
	if match == nil {
		return 0, false
	}
	n := atoi(match[1:4])
	if !validDate(n[0], n[1], n[2]) {
		return 0, false
	}
	return Day(n[0]*10000 + n[1]*100 + n[2]), true
}

// UTCDate is the UTC calendar date of an RFC 3339 date-time with an offset,
// refused when the instant falls outside years 0001 to 9999 in UTC.
func UTCDate(value string) (Day, bool) {
	match := rfc3339WithOffset.FindStringSubmatch(value)
	if match == nil {
		return 0, false
	}
	n := atoi(match[1:7])
	if n[3] > 23 || n[4] > 59 || n[5] > 59 || !validDate(n[0], n[1], n[2]) {
		return 0, false
	}
	offset := 0
	if sign := match[7]; sign != "" {
		hours, minutes := atoi(match[8:9])[0], atoi(match[9:10])[0]
		if hours > 23 || minutes > 59 {
			return 0, false
		}
		offset = hours*60 + minutes
		if sign == "-" {
			offset = -offset
		}
	}
	utc := time.Date(n[0], time.Month(n[1]), n[2], n[3], n[4]-offset, n[5], 0, time.UTC)
	if utc.Year() < 1 || utc.Year() > 9999 {
		return 0, false
	}
	return Day(utc.Year()*10000 + int(utc.Month())*100 + utc.Day()), true
}
