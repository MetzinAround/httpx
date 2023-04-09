package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/hashes"
	"github.com/projectdiscovery/httpx/common/hashes/jarm"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/httpx/common/stringz"
	"github.com/projectdiscovery/rawhttp"
	"github.com/projectdiscovery/retryablehttp-go"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// analyzeStandalone is a standalone variant of private analyze function
func (r *Runner) analyzeStandalone(hp *httpx.HTTPX, protocol string, target httpx.Target, method, origInput string, scanopts *ScanOptions) Result {
	origProtocol := protocol
	if protocol == httpx.HTTPorHTTPS || protocol == httpx.HTTPandHTTPS {
		protocol = httpx.HTTPS
	}
	retried := false
retry:
	if scanopts.VHostInput && target.CustomHost == "" {
		return Result{Input: origInput}
	}
	URL, err := r.parseURL(target.Host)
	if err != nil {
		return Result{URL: target.Host, Input: origInput, Err: err}
	}

	// check if we have to skip the host:port as a result of a previous failure
	hostPort := net.JoinHostPort(URL.Host, URL.Port())
	if r.options.HostMaxErrors >= 0 && r.HostErrorsCache.Has(hostPort) {
		numberOfErrors, err := r.HostErrorsCache.GetIFPresent(hostPort)
		if err == nil && numberOfErrors.(int) >= r.options.HostMaxErrors {
			return Result{URL: target.Host, Err: errors.New("skipping as previously unresponsive")}
		}
	}

	// check if the combination host:port should be skipped if belonging to a cdn
	if r.skipCDNPort(URL.Host, URL.Port()) {
		gologger.Debug().Msgf("Skipping cdn target: %s:%s\n", URL.Host, URL.Port())
		return Result{URL: target.Host, Input: origInput, Err: errors.New("cdn target only allows ports 80 and 443")}
	}

	URL.Scheme = protocol

	if !strings.Contains(target.Host, URL.Port()) {
		URL.TrimPort()
	}

	var reqURI string
	// retry with unsafe
	if err := URL.MergePath(scanopts.RequestURI, scanopts.Unsafe); err != nil {
		gologger.Debug().Msgf("failed to merge paths of url %v and %v", URL.String(), scanopts.RequestURI)
	}
	var req *retryablehttp.Request
	if target.CustomIP != "" {
		var requestIP string
		if iputil.IsIPv6(target.CustomIP) {
			requestIP = fmt.Sprintf("[%s]", target.CustomIP)
		} else {
			requestIP = target.CustomIP
		}
		ctx := context.WithValue(context.Background(), "ip", requestIP) //nolint
		req, err = hp.NewRequestWithContext(ctx, method, URL.String())
	} else {
		req, err = hp.NewRequest(method, URL.String())
	}
	if err != nil {
		return Result{URL: URL.String(), Input: origInput, Err: err}
	}

	if target.CustomHost != "" {
		req.Host = target.CustomHost
	}

	if !scanopts.LeaveDefaultPorts {
		switch {
		case protocol == httpx.HTTP && strings.HasSuffix(req.Host, ":80"):
			req.Host = strings.TrimSuffix(req.Host, ":80")
		case protocol == httpx.HTTPS && strings.HasSuffix(req.Host, ":443"):
			req.Host = strings.TrimSuffix(req.Host, ":443")
		}
	}

	hp.SetCustomHeaders(req, hp.CustomHeaders)
	// We set content-length even if zero to allow net/http to follow 307/308 redirects (it fails on unknown size)
	if scanopts.RequestBody != "" {
		req.ContentLength = int64(len(scanopts.RequestBody))
		req.Body = io.NopCloser(strings.NewReader(scanopts.RequestBody))
	} else {
		req.ContentLength = 0
		req.Body = nil
	}

	r.ratelimiter.Take()

	// with rawhttp we should say to the server to close the connection, otherwise it will remain open
	if scanopts.Unsafe {
		req.Header.Add("Connection", "close")
	}
	resp, err := hp.Do(req, httpx.UnsafeOptions{URIPath: reqURI})
	if r.options.ShowStatistics {
		r.stats.IncrementCounter("requests", 1)
	}
	var requestDump []byte
	if scanopts.Unsafe {
		var errDump error
		requestDump, errDump = rawhttp.DumpRequestRaw(req.Method, req.URL.String(), reqURI, req.Header, req.Body, rawhttp.DefaultOptions)
		if errDump != nil {
			return Result{URL: URL.String(), Input: origInput, Err: errDump}
		}
	} else {
		// Create a copy on the fly of the request body
		if scanopts.RequestBody != "" {
			req.ContentLength = int64(len(scanopts.RequestBody))
			req.Body = io.NopCloser(strings.NewReader(scanopts.RequestBody))
		}
		var errDump error
		requestDump, errDump = httputil.DumpRequestOut(req.Request, true)
		if errDump != nil {
			return Result{URL: URL.String(), Input: origInput, Err: errDump}
		}
		// The original req.Body gets modified indirectly by httputil.DumpRequestOut so we set it again to nil if it was empty
		// Otherwise redirects like 307/308 would fail (as they require the body to be sent along)
		if len(scanopts.RequestBody) == 0 {
			req.ContentLength = 0
			req.Body = nil
		}
	}
	// fix the final output url
	fullURL := req.URL.String()
	if parsedURL, errParse := r.parseURL(fullURL); errParse != nil {
		return Result{URL: URL.String(), Input: origInput, Err: errParse}
	} else {
		if r.options.Unsafe {
			parsedURL.Path = reqURI
			// if the full url doesn't end with the custom path we pick the original input value
		} else if !stringsutil.HasSuffixAny(fullURL, scanopts.RequestURI) {
			parsedURL.Path = scanopts.RequestURI
		}
		fullURL = parsedURL.String()
	}

	if r.options.Debug || r.options.DebugRequests {
		gologger.Info().Msgf("Dumped HTTP request for %s\n\n", fullURL)
		gologger.Print().Msgf("%s", string(requestDump))
	}
	if (r.options.Debug || r.options.DebugResponse) && resp != nil {
		gologger.Info().Msgf("Dumped HTTP response for %s\n\n", fullURL)
		gologger.Print().Msgf("%s", string(resp.Raw))
	}

	if err != nil {
		errString := ""
		errString = err.Error()
		splitErr := strings.Split(errString, ":")
		errString = strings.TrimSpace(splitErr[len(splitErr)-1])

		if !retried && origProtocol == httpx.HTTPorHTTPS {
			if protocol == httpx.HTTPS {
				protocol = httpx.HTTP
			} else {
				protocol = httpx.HTTPS
			}
			retried = true
			goto retry
		}

		// mark the host:port as failed to avoid further checks
		if r.options.HostMaxErrors >= 0 {
			errorCount, err := r.HostErrorsCache.GetIFPresent(hostPort)
			if err != nil || errorCount == nil {
				_ = r.HostErrorsCache.Set(hostPort, 1)
			} else if errorCount != nil {
				_ = r.HostErrorsCache.Set(hostPort, errorCount.(int)+1)
			}
		}

		if r.options.Probe {
			return Result{URL: URL.String(), Input: origInput, Timestamp: time.Now(), Err: err, Failed: err != nil, Error: errString}
		} else {
			return Result{URL: URL.String(), Input: origInput, Timestamp: time.Now(), Err: err}
		}
	}

	title := httpx.ExtractTitle(resp)
	serverHeader := resp.GetHeader("Server")

	var (
		serverResponseRaw string
		request           string
		rawResponseHeader string
		responseHeader    map[string]interface{}
	)

	respData := string(resp.Data)
	if r.options.NoDecode {
		respData = string(resp.RawData)
	}

	if scanopts.ResponseInStdout || r.options.OutputMatchCondition != "" || r.options.OutputFilterCondition != "" {
		serverResponseRaw = string(respData)
		request = string(requestDump)
		responseHeader = normalizeHeaders(resp.Headers)
		rawResponseHeader = resp.RawHeaders
	} else if scanopts.Base64ResponseInStdout {
		serverResponseRaw = stringz.Base64([]byte(respData))
		request = stringz.Base64(requestDump)
		responseHeader = normalizeHeaders(resp.Headers)
		rawResponseHeader = stringz.Base64([]byte(resp.RawHeaders))
	}

	// check for virtual host
	isvhost := false
	if scanopts.VHost {
		r.ratelimiter.Take()
		isvhost, _ = hp.IsVirtualHost(req, httpx.UnsafeOptions{})
	}

	// web socket
	isWebSocket := resp.StatusCode == 101

	pipeline := false
	if scanopts.Pipeline {
		port, _ := strconv.Atoi(URL.Port())
		r.ratelimiter.Take()
		pipeline = hp.SupportPipeline(protocol, method, URL.Host, port)
	}

	var http2 bool
	// if requested probes for http2
	if scanopts.HTTP2Probe {
		r.ratelimiter.Take()
		http2 = hp.SupportHTTP2(protocol, method, URL.String())
	}

	var ip string
	if target.CustomIP != "" {
		ip = target.CustomIP
	} else {
		// hp.Dialer.GetDialedIP would return only the last dialed one
		ip = hp.Dialer.GetDialedIP(URL.Host)
		if ip == "" {
			if onlyHost, _, err := net.SplitHostPort(URL.Host); err == nil {
				ip = hp.Dialer.GetDialedIP(onlyHost)
			}
		}
	}

	var asnResponse *AsnResponse
	if r.options.Asn {
		results, _ := asnmap.DefaultClient.GetData(ip)
		if len(results) > 0 {
			var cidrs []string
			ipnets, _ := asnmap.GetCIDR(results)
			for _, ipnet := range ipnets {
				cidrs = append(cidrs, ipnet.String())
			}
			asnResponse = &AsnResponse{
				AsNumber:  fmt.Sprintf("AS%v", results[0].ASN),
				AsName:    results[0].Org,
				AsCountry: results[0].Country,
				AsRange:   cidrs,
			}
		}
	}

	ips, cnames, err := getDNSData(hp, URL.Host)
	if err != nil {
		ips = append(ips, ip)
	}
	isCDN, cdnName, err := hp.CdnCheck(ip)

	var technologies []string
	if scanopts.TechDetect {
		matches := r.wappalyzer.Fingerprint(resp.Headers, resp.Data)
		for match := range matches {
			technologies = append(technologies, match)
		}
	}

	var extractRegex []string
	// extract regex
	var extractResult = map[string][]string{}
	if scanopts.extractRegexps != nil {
		for regex, compiledRegex := range scanopts.extractRegexps {
			matches := compiledRegex.FindAllString(string(resp.Raw), -1)
			if len(matches) > 0 {
				matches = sliceutil.Dedupe(matches)
				extractResult[regex] = matches
			}
		}
	}

	var finalURL string
	if resp.HasChain() {
		finalURL = resp.GetChainLastURL()
	}

	var faviconMMH3, faviconPath string
	if scanopts.Favicon {
		var err error
		faviconMMH3, faviconPath, err = r.handleFaviconHash(hp, req, resp)
		if err != nil {
			gologger.Warning().Msgf("could not calculate favicon hash for path %v : %s", faviconPath, err)
		}
	}

	// adding default hashing for json output format
	if r.options.JSONOutput && len(scanopts.Hashes) == 0 {
		scanopts.Hashes = "md5,mmh3,sha256,simhash"
	}
	hashesMap := make(map[string]interface{})
	if scanopts.Hashes != "" {
		hs := strings.Split(scanopts.Hashes, ",")
		for _, hashType := range hs {
			var (
				hashHeader, hashBody string
			)
			hashType = strings.ToLower(hashType)
			switch hashType {
			case "md5":
				hashBody = hashes.Md5(resp.Data)
				hashHeader = hashes.Md5([]byte(resp.RawHeaders))
			case "mmh3":
				hashBody = hashes.Mmh3(resp.Data)
				hashHeader = hashes.Mmh3([]byte(resp.RawHeaders))
			case "sha1":
				hashBody = hashes.Sha1(resp.Data)
				hashHeader = hashes.Sha1([]byte(resp.RawHeaders))
			case "sha256":
				hashBody = hashes.Sha256(resp.Data)
				hashHeader = hashes.Sha256([]byte(resp.RawHeaders))
			case "sha512":
				hashBody = hashes.Sha512(resp.Data)
				hashHeader = hashes.Sha512([]byte(resp.RawHeaders))
			case "simhash":
				hashBody = hashes.Simhash(resp.Data)
				hashHeader = hashes.Simhash([]byte(resp.RawHeaders))
			}
			if hashBody != "" {
				hashesMap[fmt.Sprintf("body_%s", hashType)] = hashBody
				hashesMap[fmt.Sprintf("header_%s", hashType)] = hashHeader
			}
		}
	}
	jarmhash := ""
	if r.options.Jarm {
		jarmhash = jarm.Jarm(r.fastdialer, fullURL, r.options.Timeout)
	}

	parsed, err := r.parseURL(fullURL)
	if err != nil {
		return Result{URL: fullURL, Input: origInput, Err: errors.Wrap(err, "could not parse url")}
	}

	finalPort := parsed.Port()
	if finalPort == "" {
		if parsed.Scheme == "http" {
			finalPort = "80"
		} else {
			finalPort = "443"
		}
	}
	finalPath := parsed.RequestURI()
	if finalPath == "" {
		finalPath = "/"
	}
	var chainItems []httpx.ChainItem
	var chainStatusCodes []int
	if resp.HasChain() {
		chainItems = append(chainItems, resp.GetChainAsSlice()...)
		chainStatusCodes = append(chainStatusCodes, resp.GetChainStatusCodes()...)
	}

	result := Result{
		Timestamp:        time.Now(),
		Request:          request,
		ResponseHeader:   responseHeader,
		RawHeader:        rawResponseHeader,
		Scheme:           parsed.Scheme,
		Port:             finalPort,
		Path:             finalPath,
		URL:              fullURL,
		Input:            origInput,
		ContentLength:    resp.ContentLength,
		ChainStatusCodes: chainStatusCodes,
		Chain:            chainItems,
		StatusCode:       resp.StatusCode,
		Location:         resp.GetHeaderPart("Location", ";"),
		ContentType:      resp.GetHeaderPart("Content-Type", ";"),
		Title:            title,
		VHost:            isvhost,
		WebServer:        serverHeader,
		ResponseBody:     serverResponseRaw,
		WebSocket:        isWebSocket,
		TLSData:          resp.TLSData,
		CSPData:          resp.CSPData,
		Pipeline:         pipeline,
		HTTP2:            http2,
		Method:           method,
		Host:             ip,
		A:                ips,
		CNAMEs:           cnames,
		CDN:              isCDN,
		CDNName:          cdnName,
		ResponseTime:     resp.Duration.String(),
		Technologies:     technologies,
		FinalURL:         finalURL,
		FavIconMMH3:      faviconMMH3,
		FaviconPath:      faviconPath,
		Hashes:           hashesMap,
		Extracts:         extractResult,
		Jarm:             jarmhash,
		Lines:            resp.Lines,
		Words:            resp.Words,
		ASN:              asnResponse,
		ExtractRegex:     extractRegex,
	}
	if r.options.OnResult != nil {
		r.options.OnResult(result)
	}
	return result

}
