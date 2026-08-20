package logging

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const maxAuditLogBytes = 50 * 1024 * 1024

var sensitiveQueryKeys = map[string]struct{}{
	"token": {},
	"access_token": {},
	"auth_token": {},
	"api_key": {},
	"apikey": {},
	"key": {},
	"password": {},
	"passwd": {},
	"pass": {},
	"secret": {},
	"session": {},
	"sessionid": {},
	"session_id": {},
	"sid": {},
	"email": {},
}

type AuditEntry struct { Timestamp string `json:"timestamp"`; Service string `json:"service"`; RequestID string `json:"request_id,omitempty"`; Decision string `json:"decision"`; RemoteIP string `json:"remote_ip,omitempty"`; Method string `json:"method,omitempty"`; Path string `json:"path,omitempty"`; Query string `json:"query,omitempty"`; Status int `json:"status,omitempty"`; Reason string `json:"reason,omitempty"`; RuleID string `json:"rule_id,omitempty"`; Category string `json:"category,omitempty"`; Severity string `json:"severity,omitempty"`; UserAgent string `json:"user_agent,omitempty"`; Bytes int64 `json:"bytes,omitempty"`; WAFEnabled bool `json:"waf_enabled"`; Target string `json:"target,omitempty"` }
type Stats struct { Total int `json:"total"`; Allowed int `json:"allowed"`; Blocked int `json:"blocked"`; Controls int `json:"controls"`; Reasons map[string]int `json:"reasons"`; RecentBlocked []AuditEntry `json:"recent_blocked"` }
type Auditor struct { path string; mu sync.Mutex }
func New(path string)*Auditor{return &Auditor{path:path}}
func(a *Auditor)Path()string{return a.path}
func(a *Auditor)Write(entry AuditEntry)error{a.mu.Lock();defer a.mu.Unlock();if err:=os.MkdirAll(filepath.Dir(a.path),0700);err!=nil{return err};if err:=os.Chmod(filepath.Dir(a.path),0700);err!=nil{return err};if info,err:=os.Stat(a.path);err==nil&&info.Size()>=maxAuditLogBytes{_ = os.Remove(a.path+".1");if err:=os.Rename(a.path,a.path+".1");err!=nil{return err}};file,err:=os.OpenFile(a.path,os.O_APPEND|os.O_CREATE|os.O_WRONLY,0600);if err!=nil{return err};defer file.Close();if err:=file.Chmod(0600);err!=nil{return err};entry.Query=redactQuery(entry.Query);return json.NewEncoder(file).Encode(entry)}
func(a *Auditor)Recent(limit int)([]AuditEntry,error){if limit<=0{limit=50};lines,err:=a.readLines();if err!=nil{return nil,err};entries:=make([]AuditEntry,0,limit);for i:=len(lines)-1;i>=0&&len(entries)<limit;i--{line:=strings.TrimSpace(lines[i]);if line==""{continue};var entry AuditEntry;if err:=json.Unmarshal([]byte(line),&entry);err==nil{entries=append(entries,entry)}};return entries,nil}
func(a *Auditor)Stats()(Stats,error){lines,err:=a.readLines();if err!=nil{return Stats{},err};stats:=Stats{Reasons:map[string]int{},RecentBlocked:[]AuditEntry{}};for i:=len(lines)-1;i>=0;i--{line:=strings.TrimSpace(lines[i]);if line==""{continue};var entry AuditEntry;if err:=json.Unmarshal([]byte(line),&entry);err!=nil{continue};stats.Total++;switch entry.Decision{case "allowed":stats.Allowed++;case "blocked":stats.Blocked;if entry.Reason!=""{stats.Reasons[entry.Reason]++};if len(stats.RecentBlocked)<20{stats.RecentBlocked=append(stats.RecentBlocked,entry)};case "control":stats.Controls++}};return stats,nil}
func(a *Auditor)readLines()([]string,error){a.mu.Lock();defer a.mu.Unlock();file,err:=os.Open(a.path);if errors.Is(err,os.ErrNotExist){return []string{},nil};if err!=nil{return nil,err};defer file.Close();scanner:=bufio.NewScanner(file);scanner.Buffer(make([]byte,1024),1024*1024*5);lines:=[]string{};for scanner.Scan(){lines=append(lines,scanner.Text())};if err:=scanner.Err();err!=nil{return nil,err};return lines,nil}

func redactQuery(raw string) string {
	if raw == "" {
		return raw
	}
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		key := part
		if idx := strings.IndexByte(part, '='); idx >= 0 {
			key = part[:idx]
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			decodedKey = key
		}
		decodedKey = strings.ToLower(strings.TrimSpace(decodedKey))
		if _, sensitive := sensitiveQueryKeys[decodedKey]; sensitive {
			parts[i] = key + "=REDACTED"
		}
	}
	return strings.Join(parts, "&")
}
