package export

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/eryajf/cloud_dns_exporter/pkg/provider"
)

const (
	maxConcurrency = 100
	timeout        = 10 * time.Second
)

func GetMultipleCertInfo(records []provider.GetRecordCertReq) ([]provider.RecordCert, error) {
	results := make([]provider.RecordCert, len(records))
	semaphore := make(chan struct{}, maxConcurrency)

	var wg sync.WaitGroup
	resultChan := make(chan struct {
		index int
		cert  provider.RecordCert
	}, len(records))
	go func() {
		for result := range resultChan {
			results[result.index] = result.cert
			wg.Done()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for i, record := range records {
		wg.Add(1)
		go func(i int, record provider.GetRecordCertReq) {
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()

				cert, err := GetCertInfo(record)
				if err != nil {
					cert.ErrorMsg = err.Error()
				}
				resultChan <- struct {
					index int
					cert  provider.RecordCert
				}{i, cert}
			case <-ctx.Done():
				resultChan <- struct {
					index int
					cert  provider.RecordCert
				}{i, provider.RecordCert{ErrorMsg: "operation timed out"}}
			}
		}(i, record)
	}
	wg.Wait()
	close(resultChan)

	return results, nil
}

// GetCertInfo 获取证书信息
func GetCertInfo(record provider.GetRecordCertReq) (certInfo provider.RecordCert, err error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         record.FullRecord,
	}
	d := net.Dialer{
		Timeout: time.Second * 3,
	}
	conn, err := tls.DialWithDialer(&d, "tcp", record.RecordValue+":443", config)
	if err != nil {
		return certInfo, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return certInfo, fmt.Errorf("未找到证书")
	}
	var targetCert *x509.Certificate
	var minDaysUntilExpiry int = -1 // 初始化为-1，表示未找到有效证书
	for _, cert := range certs {
		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		// 更新最小的过期时间
		if minDaysUntilExpiry == -1 || daysUntilExpiry < minDaysUntilExpiry {
			minDaysUntilExpiry = daysUntilExpiry
		}
		// 检查证书是否匹配
		if strings.Contains(certInfo.SubjectCommonName, record.DomainName) || checkCertMatched(record, cert) {
			targetCert = cert
		}
	}
	if targetCert == nil {
		return certInfo, fmt.Errorf("证书不匹配")
	}
	// certInfo.PeerCertsMinDaysUntilExpiry = minDaysUntilExpiry
	certInfo.CloudProvider = record.CloudProvider
	certInfo.CloudName = record.CloudName
	certInfo.DomainName = record.DomainName
	certInfo.FullRecord = record.FullRecord
	certInfo.RecordID = record.RecordID
	certInfo.SubjectCommonName = targetCert.Subject.CommonName
	certInfo.IssuerCommonName = targetCert.Issuer.CommonName
	certInfo.CertMatched = true
	certInfo.CreatedDate = targetCert.NotBefore.Format(time.DateOnly)
	certInfo.ExpiryDate = targetCert.NotAfter.Format(time.DateOnly)
	// daysUntilExpiry := int(time.Until(targetCert.NotAfter).Hours() / 24)
	certInfo.DaysUntilExpiry = minDaysUntilExpiry

	return certInfo, nil
}

// getNewRecord 判断域名解析记录是否符合可获取ssl证书信息的条件
func getNewRecord(records []provider.Record) (newRecords []provider.Record) {
	var wg sync.WaitGroup
	recordChan := make(chan provider.Record)
	for _, record := range records {
		wg.Add(1)
		go func(rec provider.Record) {
			defer wg.Done()
			if rec.RecordName == "@" {
				rec.FullRecord = rec.DomainName
			}
			if strings.Contains(rec.FullRecord, "*") {
				//rec.FullRecord = strings.ReplaceAll(rec.FullRecord, "*", "a")
				return
			}
			if (rec.RecordType == "A" || rec.RecordType == "CNAME") &&
				rec.RecordStatus == "enable" && isPortOpen(rec.RecordValue) {
				recordChan <- rec
			}
		}(record)
	}
	go func() {
		wg.Wait()
		close(recordChan)
	}()
	for rec := range recordChan {
		newRecords = append(newRecords, rec)
	}
	return
}

// isPortOpen 检查给定域名的443端口是否通
func isPortOpen(domain string) bool {
	timeout := 1 * time.Second
	conn, err := net.DialTimeout("tcp", domain+":443", timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// checkCertMatched 检查证书是否匹配
// https://github.com/opsre/cloud_dns_exporter/issues/25
func checkCertMatched(record provider.GetRecordCertReq, cert *x509.Certificate) bool {
	for _, name := range cert.DNSNames {
		if strings.Contains(name, record.DomainName) {
			return true
		}
	}
	return false
}
