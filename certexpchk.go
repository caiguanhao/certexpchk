package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

const YMD_HMS_FORMAT = "2006-01-02 15:04:05"

func checkIfCertsExpired(certs []*x509.Certificate) (expired bool, expiredCerts []*x509.Certificate, unexpiredCerts []*x509.Certificate) {
	now := time.Now()
	for _, cert := range certs {
		if now.Before(cert.NotAfter) && now.After(cert.NotBefore) {
			unexpiredCerts = append(unexpiredCerts, cert)
		} else {
			expired = true
			expiredCerts = append(expiredCerts, cert)
		}
	}
	return
}

func certSummary(cert *x509.Certificate) (summary string) {
	var ret []string
	if len(cert.Subject.Organization) > 0 {
		for _, o := range cert.Subject.Organization {
			ret = append(ret, fmt.Sprintf("O=%s", o))
		}
	}
	ret = append(ret, fmt.Sprintf("CN=%s", cert.Subject.CommonName))
	return strings.Join(ret, ", ")
}

var isVerbose bool

func init() {
	flag.BoolVar(&isVerbose, "verbose", false, "")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s [OPTION] HOSTNAME[:PORT] ...\n", path.Base(os.Args[0]))
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Option:")
		fmt.Fprintln(os.Stderr, "    --verbose    show more output")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Status code indicates how many certificates have expired.")
	}
	flag.Parse()
}

func main() {
	var wg sync.WaitGroup
	var code int = 0
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	config := &tls.Config{InsecureSkipVerify: true}
	for _, host := range flag.Args() {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if strings.LastIndex(host, ":") == -1 {
				host = host + ":443"
			}
			if isVerbose {
				fmt.Fprintf(os.Stderr, "[%s] getting and checking cert...\n", host)
			}
			conn, err := tls.DialWithDialer(dialer, "tcp", host, config)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] ", host)
				fmt.Fprintln(os.Stderr, err)
				code += 1
				return
			}
			defer conn.Close()
			expired, expiredCerts, unexpiredCerts := checkIfCertsExpired(conn.ConnectionState().PeerCertificates)
			if expired {
				for _, cert := range expiredCerts {
					fmt.Fprintf(os.Stderr, "[%s] cert of %s has expired! (%s - %s)\n",
						host,
						certSummary(cert),
						cert.NotBefore.Format(YMD_HMS_FORMAT),
						cert.NotAfter.Format(YMD_HMS_FORMAT))
					code += 1
				}
				return
			}
			for _, cert := range unexpiredCerts {
				if isVerbose {
					fmt.Fprintf(os.Stderr, "[%s] cert of %s has not yet expired.\n",
						host,
						certSummary(cert),
					)
				}
			}
		}(host)
	}
	wg.Wait()
	os.Exit(code)
}
