package proxyd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/rs/cors"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	ContextKeyAuth               = "authorization"
	ContextKeyReqID              = "req_id"
	ContextKeyXForwardedFor      = "x_forwarded_for"
	DefaultMaxBatchRPCCallsLimit = 100
	MaxBatchRPCCallsHardLimit    = 1000
	cacheStatusHdr               = "X-Proxyd-Cache-Status"
	defaultRPCTimeout            = 10 * time.Second
	defaultBodySizeLimit         = 256 * opt.KiB
	defaultWSHandshakeTimeout    = 10 * time.Second
	defaultWSReadTimeout         = 2 * time.Minute
	defaultWSWriteTimeout        = 10 * time.Second
	defaultCacheTtl              = 1 * time.Hour
	maxRequestBodyLogLen         = 2000
	defaultMaxUpstreamBatchSize  = 10
	defaultRateLimitHeader       = "X-Forwarded-For"
)

var emptyArrayResponse = json.RawMessage("[]")
var tracer = otel.Tracer("proxyd-server")

type Server struct {
	BackendGroups          map[string]*BackendGroup
	wsBackendGroup         *BackendGroup
	wsMethodWhitelist      *StringSet
	rpcMethodMappings      map[string]string
	maxBodySize            int64
	enableRequestLog       bool
	maxRequestBodyLogLen   int
	authenticatedPaths     map[string]string
	timeout                time.Duration
	maxUpstreamBatchSize   int
	maxBatchSize           int
	enableServedByHeader   bool
	upgrader               *websocket.Upgrader
	mainLim                FrontendRateLimiter
	overrideLims           map[string]FrontendRateLimiter
	senderLim              FrontendRateLimiter
	allowedChainIds        []*big.Int
	limExemptOrigins       []*regexp.Regexp
	limExemptUserAgents    []*regexp.Regexp
	globallyLimitedMethods map[string]bool
	rpcServer              *http.Server
	wsServer               *http.Server
	cache                  RPCCache
	srvMu                  sync.Mutex
	rateLimitHeader        string
	sanctionedAddresses    map[common.Address]struct{}
}

type limiterFunc func(method string) bool

func NewServer(
	backendGroups map[string]*BackendGroup,
	wsBackendGroup *BackendGroup,
	wsMethodWhitelist *StringSet,
	rpcMethodMappings map[string]string,
	maxBodySize int64,
	authenticatedPaths map[string]string,
	timeout time.Duration,
	maxUpstreamBatchSize int,
	enableServedByHeader bool,
	cache RPCCache,
	rateLimitConfig RateLimitConfig,
	senderRateLimitConfig SenderRateLimitConfig,
	enableRequestLog bool,
	maxRequestBodyLogLen int,
	maxBatchSize int,
	redisClient *redis.Client,
	sanctionedAddresses map[common.Address]struct{},
) (*Server, error) {
	if cache == nil {
		cache = &NoopRPCCache{}
	}

	if maxBodySize == 0 {
		maxBodySize = defaultBodySizeLimit
	}

	if timeout == 0 {
		timeout = defaultRPCTimeout
	}

	if maxUpstreamBatchSize == 0 {
		maxUpstreamBatchSize = defaultMaxUpstreamBatchSize
	}

	if maxBatchSize == 0 {
		maxBatchSize = DefaultMaxBatchRPCCallsLimit
	}

	if maxBatchSize > MaxBatchRPCCallsHardLimit {
		maxBatchSize = MaxBatchRPCCallsHardLimit
	}

	limiterFactory := func(dur time.Duration, max int, prefix string) FrontendRateLimiter {
		if rateLimitConfig.UseRedis {
			return NewRedisFrontendRateLimiter(redisClient, dur, max, prefix)
		}

		return NewMemoryFrontendRateLimit(dur, max)
	}

	var mainLim FrontendRateLimiter
	limExemptOrigins := make([]*regexp.Regexp, 0)
	limExemptUserAgents := make([]*regexp.Regexp, 0)
	if rateLimitConfig.BaseRate > 0 {
		mainLim = limiterFactory(time.Duration(rateLimitConfig.BaseInterval), rateLimitConfig.BaseRate, "main")
		for _, origin := range rateLimitConfig.ExemptOrigins {
			pattern, err := regexp.Compile(origin)
			if err != nil {
				return nil, err
			}
			limExemptOrigins = append(limExemptOrigins, pattern)
		}
		for _, agent := range rateLimitConfig.ExemptUserAgents {
			pattern, err := regexp.Compile(agent)
			if err != nil {
				return nil, err
			}
			limExemptUserAgents = append(limExemptUserAgents, pattern)
		}
	} else {
		mainLim = NoopFrontendRateLimiter
	}

	overrideLims := make(map[string]FrontendRateLimiter)
	globalMethodLims := make(map[string]bool)
	for method, override := range rateLimitConfig.MethodOverrides {
		overrideLims[method] = limiterFactory(time.Duration(override.Interval), override.Limit, method)

		if override.Global {
			globalMethodLims[method] = true
		}
	}
	var senderLim FrontendRateLimiter
	if senderRateLimitConfig.Enabled {
		senderLim = limiterFactory(time.Duration(senderRateLimitConfig.Interval), senderRateLimitConfig.Limit, "senders")
	}

	rateLimitHeader := defaultRateLimitHeader
	if rateLimitConfig.IPHeaderOverride != "" {
		rateLimitHeader = rateLimitConfig.IPHeaderOverride
	}

	return &Server{
		BackendGroups:        backendGroups,
		wsBackendGroup:       wsBackendGroup,
		wsMethodWhitelist:    wsMethodWhitelist,
		rpcMethodMappings:    rpcMethodMappings,
		maxBodySize:          maxBodySize,
		authenticatedPaths:   authenticatedPaths,
		timeout:              timeout,
		maxUpstreamBatchSize: maxUpstreamBatchSize,
		enableServedByHeader: enableServedByHeader,
		cache:                cache,
		enableRequestLog:     enableRequestLog,
		maxRequestBodyLogLen: maxRequestBodyLogLen,
		maxBatchSize:         maxBatchSize,
		upgrader: &websocket.Upgrader{
			HandshakeTimeout: defaultWSHandshakeTimeout,
		},
		mainLim:                mainLim,
		overrideLims:           overrideLims,
		globallyLimitedMethods: globalMethodLims,
		senderLim:              senderLim,
		allowedChainIds:        senderRateLimitConfig.AllowedChainIds,
		limExemptOrigins:       limExemptOrigins,
		limExemptUserAgents:    limExemptUserAgents,
		rateLimitHeader:        rateLimitHeader,
		sanctionedAddresses:    sanctionedAddresses,
	}, nil
}

func (s *Server) RPCListenAndServe(host string, port int) error {
	s.srvMu.Lock()
	hdlr := mux.NewRouter()

	// Non-instrumented methods
	hdlr.HandleFunc("/healthz", s.HandleHealthz).Methods("GET")
	// hdlr.HandleFunc("/", s.HandleRPC).Methods("POST")
	// hdlr.HandleFunc("/{authorization}", s.HandleRPC).Methods("POST")

	// Instrumented methods
	// hdlr.Handle("/healthz", otelhttp.NewHandler(http.HandlerFunc(s.HandleHealthz), "HealthzHandler")).Methods("GET")
	hdlr.Handle("/", otelhttp.NewHandler(http.HandlerFunc(s.HandleRPC),
		"RPCHandler",
		otelhttp.WithSpanOptions(trace.WithAttributes(
			attribute.Bool("force_sample", true),
		)),
	)).Methods("POST")
	hdlr.Handle("/{authorization}", otelhttp.NewHandler(http.HandlerFunc(s.HandleRPC), "RPCHandler")).Methods("POST")

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
	})
	addr := fmt.Sprintf("%s:%d", host, port)
	s.rpcServer = &http.Server{
		Handler: instrumentedHdlr(c.Handler(hdlr)),
		Addr:    addr,
	}
	log.Info("starting HTTP server", "addr", addr)
	s.srvMu.Unlock()
	return s.rpcServer.ListenAndServe()
}

func (s *Server) WSListenAndServe(host string, port int) error {
	s.srvMu.Lock()
	hdlr := mux.NewRouter()
	hdlr.HandleFunc("/", s.HandleWS)
	hdlr.HandleFunc("/{authorization}", s.HandleWS)
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
	})
	addr := fmt.Sprintf("%s:%d", host, port)
	s.wsServer = &http.Server{
		Handler: instrumentedHdlr(c.Handler(hdlr)),
		Addr:    addr,
	}
	log.Info("starting WS server", "addr", addr)
	s.srvMu.Unlock()
	return s.wsServer.ListenAndServe()
}

func (s *Server) Shutdown() {
	s.srvMu.Lock()
	defer s.srvMu.Unlock()
	if s.rpcServer != nil {
		_ = s.rpcServer.Shutdown(context.Background())
	}
	if s.wsServer != nil {
		_ = s.wsServer.Shutdown(context.Background())
	}
	for _, bg := range s.BackendGroups {
		bg.Shutdown()
	}
}

func (s *Server) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	// _, span := tracer.Start(r.Context(), "HealthzFunction")
	// defer span.End()

	_, _ = w.Write([]byte("OK"))
}

func (s *Server) HandleRPC(w http.ResponseWriter, r *http.Request) {

	_, span := tracer.Start(r.Context(), "RPCFunction")
	defer span.End()

	ctx := s.populateContext(w, r)
	if ctx == nil {
		return
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, s.timeout)
	defer cancel()

	origin := r.Header.Get("Origin")
	userAgent := r.Header.Get("User-Agent")
	// Use XFF in context since it will automatically be replaced by the remote IP
	xff := stripXFF(GetXForwardedFor(ctx))
	isUnlimitedOrigin := s.isUnlimitedOrigin(origin)
	isUnlimitedUserAgent := s.isUnlimitedUserAgent(userAgent)

	if xff == "" {
		writeRPCError(ctx, w, nil, ErrInvalidRequest("request does not include a remote IP"))
		return
	}

	isLimited := func(method string) bool {
		isGloballyLimitedMethod := s.isGlobalLimit(method)
		if !isGloballyLimitedMethod && (isUnlimitedOrigin || isUnlimitedUserAgent) {
			return false
		}

		var lim FrontendRateLimiter
		if method == "" {
			lim = s.mainLim
		} else {
			lim = s.overrideLims[method]
		}

		if lim == nil {
			return false
		}

		ok, err := lim.Take(ctx, xff)
		if err != nil {
			log.Warn("error taking rate limit", "err", err)
			return true
		}
		return !ok
	}

	log.Debug(
		"received RPC request",
		"req_id", GetReqID(ctx),
		"auth", GetAuthCtx(ctx),
		"user_agent", userAgent,
		"origin", origin,
		"remote_ip", xff,
	)

	body, err := io.ReadAll(LimitReader(r.Body, s.maxBodySize))
	if errors.Is(err, ErrLimitReaderOverLimit) {
		log.Error("request body too large", "req_id", GetReqID(ctx))
		RecordRPCError(ctx, BackendProxyd, MethodUnknown, ErrRequestBodyTooLarge)
		writeRPCError(ctx, w, nil, ErrRequestBodyTooLarge)
		return
	}
	if err != nil {
		log.Error("error reading request body", "err", err)
		writeRPCError(ctx, w, nil, ErrInternal)
		return
	}
	RecordRequestPayloadSize(ctx, len(body))

	if s.enableRequestLog {
		log.Info("Raw RPC request",
			"body", truncate(string(body), s.maxRequestBodyLogLen),
			"req_id", GetReqID(ctx),
			"auth", GetAuthCtx(ctx),
		)
	}

	if IsBatch(body) {
		reqs, err := ParseBatchRPCReq(body)
		if err != nil {
			log.Error("error parsing batch RPC request", "err", err)
			RecordRPCError(ctx, BackendProxyd, MethodUnknown, err)
			writeRPCError(ctx, w, nil, ErrParseErr)
			return
		}

		RecordBatchSize(len(reqs))

		if len(reqs) > s.maxBatchSize {
			RecordRPCError(ctx, BackendProxyd, MethodUnknown, ErrTooManyBatchRequests)
			writeRPCError(ctx, w, nil, ErrTooManyBatchRequests)
			return
		}

		if len(reqs) == 0 {
			writeRPCError(ctx, w, nil, ErrInvalidRequest("must specify at least one batch call"))
			return
		}

		batchRes, batchContainsCached, servedBy, err := s.handleBatchRPC(ctx, reqs, isLimited, true)
		if err == context.DeadlineExceeded {
			writeRPCError(ctx, w, nil, ErrGatewayTimeout)
			return
		}
		if errors.Is(err, ErrConsensusGetReceiptsCantBeBatched) ||
			errors.Is(err, ErrConsensusGetReceiptsInvalidTarget) {
			writeRPCError(ctx, w, nil, ErrInvalidRequest(err.Error()))
			return
		}
		if err != nil {
			writeRPCError(ctx, w, nil, ErrInternal)
			return
		}
		if s.enableServedByHeader {
			w.Header().Set("x-served-by", servedBy)
		}
		setCacheHeader(w, batchContainsCached)
		writeBatchRPCRes(ctx, w, batchRes)
		return
	}

	rawBody := json.RawMessage(body)
	backendRes, cached, servedBy, err := s.handleBatchRPC(ctx, []json.RawMessage{rawBody}, isLimited, false)
	if err != nil {
		if errors.Is(err, ErrConsensusGetReceiptsCantBeBatched) ||
			errors.Is(err, ErrConsensusGetReceiptsInvalidTarget) {
			writeRPCError(ctx, w, nil, ErrInvalidRequest(err.Error()))
			return
		}
		writeRPCError(ctx, w, nil, ErrInternal)
		return
	}
	if s.enableServedByHeader {
		w.Header().Set("x-served-by", servedBy)
	}
	setCacheHeader(w, cached)
	writeRPCRes(ctx, w, backendRes[0])
}

func (s *Server) handleBatchRPC(ctx context.Context, reqs []json.RawMessage, isLimited limiterFunc, isBatch bool) ([]*RPCRes, bool, string, error) {

	_, span := tracer.Start(ctx, "BatchRPCFunction")
	defer span.End()

	// A request set is transformed into groups of batches.
	// Each batch group maps to a forwarded JSON-RPC batch request (subject to maxUpstreamBatchSize constraints)
	// A groupID is used to decouple Requests that have duplicate ID so they're not part of the same batch that's
	// forwarded to the backend. This is done to ensure that the order of JSON-RPC Responses match the Request order
	// as the backend MAY return Responses out of order.
	// NOTE: Duplicate request ids induces 1-sized JSON-RPC batches
	type batchGroup struct {
		groupID      int
		backendGroup string
	}

	responses := make([]*RPCRes, len(reqs))
	batches := make(map[batchGroup][]batchElem)
	ids := make(map[string]int, len(reqs))

	for i := range reqs {
		parsedReq, err := ParseRPCReq(reqs[i])
		if err != nil {
			log.Info("error parsing RPC call", "source", "rpc", "err", err)
			responses[i] = NewRPCErrorRes(nil, err)
			continue
		}

		// Simple health check
		if len(reqs) == 1 && parsedReq.Method == proxydHealthzMethod {
			res := &RPCRes{
				ID:      parsedReq.ID,
				JSONRPC: JSONRPCVersion,
				Result:  "OK",
			}
			return []*RPCRes{res}, false, "", nil
		}

		if err := ValidateRPCReq(parsedReq); err != nil {
			RecordRPCError(ctx, BackendProxyd, MethodUnknown, err)
			responses[i] = NewRPCErrorRes(nil, err)
			continue
		}

		if parsedReq.Method == "eth_accounts" {
			RecordRPCForward(ctx, BackendProxyd, "eth_accounts", RPCRequestSourceHTTP)
			responses[i] = NewRPCRes(parsedReq.ID, emptyArrayResponse)
			continue
		}

		group := s.rpcMethodMappings[parsedReq.Method]
		if group == "" {
			// use unknown below to prevent DOS vector that fills up memory
			// with arbitrary method names.
			log.Info(
				"blocked request for non-whitelisted method",
				"source", "rpc",
				"req_id", GetReqID(ctx),
				"method", parsedReq.Method,
			)
			RecordRPCError(ctx, BackendProxyd, MethodUnknown, ErrMethodNotWhitelisted)
			responses[i] = NewRPCErrorRes(parsedReq.ID, ErrMethodNotWhitelisted)
			continue
		}

		// Take base rate limit first
		if isLimited("") {
			log.Debug(
				"rate limited individual RPC in a batch request",
				"source", "rpc",
				"req_id", parsedReq.ID,
				"method", parsedReq.Method,
			)
			RecordRPCError(ctx, BackendProxyd, parsedReq.Method, ErrOverRateLimit)
			responses[i] = NewRPCErrorRes(parsedReq.ID, ErrOverRateLimit)
			continue
		}

		// Take rate limit for specific methods.
		if _, ok := s.overrideLims[parsedReq.Method]; ok && isLimited(parsedReq.Method) {
			log.Debug(
				"rate limited specific RPC",
				"source", "rpc",
				"req_id", GetReqID(ctx),
				"method", parsedReq.Method,
			)
			RecordRPCError(ctx, BackendProxyd, parsedReq.Method, ErrOverRateLimit)
			responses[i] = NewRPCErrorRes(parsedReq.ID, ErrOverRateLimit)
			continue
		}

		// Check if the sender is sanctioned.
		if parsedReq.Method == "eth_sendRawTransaction" && s.sanctionedAddresses != nil {
			if err := s.filterSanctionedAddresses(ctx, parsedReq); err != nil {
				RecordRPCError(ctx, BackendProxyd, parsedReq.Method, err)
				responses[i] = NewRPCErrorRes(parsedReq.ID, err)
				continue
			}
		}

		// Apply a sender-based rate limit if it is enabled. Note that sender-based rate
		// limits apply regardless of origin or user-agent. As such, they don't use the
		// isLimited method.
		if parsedReq.Method == "eth_sendRawTransaction" && s.senderLim != nil {
			if err := s.rateLimitSender(ctx, parsedReq); err != nil {
				RecordRPCError(ctx, BackendProxyd, parsedReq.Method, err)
				responses[i] = NewRPCErrorRes(parsedReq.ID, err)
				continue
			}
		}

		id := string(parsedReq.ID)
		// If this is a duplicate Request ID, move the Request to a new batchGroup
		ids[id]++
		batchGroupID := ids[id]
		batchGroup := batchGroup{groupID: batchGroupID, backendGroup: group}
		batches[batchGroup] = append(batches[batchGroup], batchElem{parsedReq, i})
	}

	servedBy := make(map[string]bool, 0)
	var cached bool
	for group, batch := range batches {
		var cacheMisses []batchElem

		for _, req := range batch {
			backendRes, _ := s.cache.GetRPC(ctx, req.Req)
			if backendRes != nil {
				responses[req.Index] = backendRes
				cached = true
			} else {
				cacheMisses = append(cacheMisses, req)
			}
		}

		// Create minibatches - each minibatch must be no larger than the maxUpstreamBatchSize
		numBatches := int(math.Ceil(float64(len(cacheMisses)) / float64(s.maxUpstreamBatchSize)))
		for i := 0; i < numBatches; i++ {
			if ctx.Err() == context.DeadlineExceeded {
				log.Info("short-circuiting batch RPC",
					"req_id", GetReqID(ctx),
					"auth", GetAuthCtx(ctx),
					"batch_index", i,
				)
				batchRPCShortCircuitsTotal.Inc()
				return nil, false, "", context.DeadlineExceeded
			}

			start := i * s.maxUpstreamBatchSize
			end := int(math.Min(float64(start+s.maxUpstreamBatchSize), float64(len(cacheMisses))))
			elems := cacheMisses[start:end]
			res, sb, err := s.BackendGroups[group.backendGroup].Forward(ctx, createBatchRequest(elems), isBatch)
			servedBy[sb] = true
			if err != nil {
				if errors.Is(err, ErrConsensusGetReceiptsCantBeBatched) ||
					errors.Is(err, ErrConsensusGetReceiptsInvalidTarget) {
					return nil, false, "", err
				}
				log.Error(
					"error forwarding RPC batch",
					"batch_size", len(elems),
					"backend_group", group,
					"req_id", GetReqID(ctx),
					"err", err,
				)
				res = nil
				for _, elem := range elems {
					res = append(res, NewRPCErrorRes(elem.Req.ID, err))
				}
			}

			for i := range elems {
				responses[elems[i].Index] = res[i]

				// TODO(inphi): batch put these
				if res[i].Error == nil && res[i].Result != nil {
					if err := s.cache.PutRPC(ctx, elems[i].Req, res[i]); err != nil {
						log.Warn(
							"cache put error",
							"req_id", GetReqID(ctx),
							"err", err,
						)
					}
				}
			}
		}
	}

	servedByString := ""
	for sb := range servedBy {
		if servedByString != "" {
			servedByString += ", "
		}
		servedByString += sb
	}

	return responses, cached, servedByString, nil
}

func (s *Server) HandleWS(w http.ResponseWriter, r *http.Request) {
	ctx := s.populateContext(w, r)
	if ctx == nil {
		return
	}

	log.Info("received WS connection", "req_id", GetReqID(ctx))

	clientConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("error upgrading client conn", "auth", GetAuthCtx(ctx), "req_id", GetReqID(ctx), "err", err)
		return
	}
	clientConn.SetReadLimit(s.maxBodySize)

	proxier, err := s.wsBackendGroup.ProxyWS(ctx, clientConn, s.wsMethodWhitelist, s)
	if err != nil {
		if errors.Is(err, ErrNoBackends) {
			RecordUnserviceableRequest(ctx, RPCRequestSourceWS)
		}
		log.Error("error dialing ws backend", "auth", GetAuthCtx(ctx), "req_id", GetReqID(ctx), "err", err)
		clientConn.Close()
		return
	}

	activeClientWsConnsGauge.WithLabelValues(GetAuthCtx(ctx)).Inc()
	go func() {
		// Below call blocks so run it in a goroutine.
		if err := proxier.Proxy(ctx); err != nil {
			log.Error("error proxying websocket", "auth", GetAuthCtx(ctx), "req_id", GetReqID(ctx), "err", err)
		}
		activeClientWsConnsGauge.WithLabelValues(GetAuthCtx(ctx)).Dec()
	}()

	log.Info("accepted WS connection", "auth", GetAuthCtx(ctx), "req_id", GetReqID(ctx))
}

func (s *Server) populateContext(w http.ResponseWriter, r *http.Request) context.Context {
	vars := mux.Vars(r)
	authorization := vars["authorization"]
	xff := r.Header.Get(s.rateLimitHeader)
	if xff == "" {
		ipPort := strings.Split(r.RemoteAddr, ":")
		if len(ipPort) == 2 {
			xff = ipPort[0]
		}
	}
	ctx := context.WithValue(r.Context(), ContextKeyXForwardedFor, xff) // nolint:staticcheck

	if len(s.authenticatedPaths) > 0 {
		if authorization == "" || s.authenticatedPaths[authorization] == "" {
			log.Info("blocked unauthorized request", "authorization", authorization)
			httpResponseCodesTotal.WithLabelValues("401").Inc()
			w.WriteHeader(401)
			return nil
		}

		ctx = context.WithValue(ctx, ContextKeyAuth, s.authenticatedPaths[authorization]) // nolint:staticcheck
	}

	return context.WithValue(
		ctx,
		ContextKeyReqID, // nolint:staticcheck
		randStr(10),
	)
}

func randStr(l int) string {
	b := make([]byte, l)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Server) isUnlimitedOrigin(origin string) bool {
	for _, pat := range s.limExemptOrigins {
		if pat.MatchString(origin) {
			return true
		}
	}

	return false
}

func (s *Server) isUnlimitedUserAgent(origin string) bool {
	for _, pat := range s.limExemptUserAgents {
		if pat.MatchString(origin) {
			return true
		}
	}
	return false
}

func (s *Server) isGlobalLimit(method string) bool {
	return s.globallyLimitedMethods[method]
}

func (s *Server) processTransaction(ctx context.Context, req *RPCReq) (*types.Transaction, *common.Address, error) {
	var params []string
	if err := json.Unmarshal(req.Params, &params); err != nil {
		log.Debug("error unmarshalling raw transaction params", "err", err, "req_Id", GetReqID(ctx))
		return nil, nil, ErrParseErr
	}

	if len(params) != 1 {
		log.Debug("raw transaction request has invalid number of params", "req_id", GetReqID(ctx))
		return nil, nil, ErrInvalidParams("missing value for required argument 0")
	}

	var data hexutil.Bytes
	if err := data.UnmarshalText([]byte(params[0])); err != nil {
		log.Debug("error decoding raw tx data", "err", err, "req_id", GetReqID(ctx))
		return nil, nil, ErrInvalidParams(err.Error())
	}

	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(data); err != nil {
		log.Debug("could not unmarshal transaction", "err", err, "req_id", GetReqID(ctx))
		return nil, nil, ErrInvalidParams(err.Error())
	}

	signer := types.LatestSignerForChainID(tx.ChainId())
	from, err := types.Sender(signer, tx)
	if err != nil {
		log.Debug("could not get sender from transaction with LatestSignerForChainID", "err", err, "req_id", GetReqID(ctx))
		return nil, nil, ErrInvalidParams(err.Error())
	}

	return tx, &from, nil
}

// CheckSanctionedAddresses checks if a request involves any sanctioned addresses
func (s *Server) CheckSanctionedAddresses(ctx context.Context, req *RPCReq) error {
	if req.Method != "eth_sendRawTransaction" || s.sanctionedAddresses == nil {
		return nil
	}

	tx, from, err := s.processTransaction(ctx, req)
	if err != nil {
		return err
	}

	if _, ok := s.sanctionedAddresses[*from]; ok {
		log.Debug("sender is sanctioned", "sender", from, "req_id", GetReqID(ctx))
		return ErrNoBackends
	}
	to := tx.To()
	// Create transactions do not have a "to" address so in this case "to" can be nil.
	if to != nil {
		if _, ok := s.sanctionedAddresses[*to]; ok {
			log.Debug("recipient is sanctioned", "recipient", to, "req_id", GetReqID(ctx))
			return ErrNoBackends
		}
	}

	return nil
}

func (s *Server) filterSanctionedAddresses(ctx context.Context, req *RPCReq) error {
	return s.CheckSanctionedAddresses(ctx, req)
}

func (s *Server) rateLimitSender(ctx context.Context, req *RPCReq) error {
	tx, from, err := s.processTransaction(ctx, req)
	if err != nil {
		return err
	}

	if !s.isAllowedChainId(tx.ChainId()) {
		log.Debug("chain id is not allowed", "req_id", GetReqID(ctx))
		return txpool.ErrInvalidSender
	}

	ok, err := s.senderLim.Take(ctx, fmt.Sprintf("%s:%d", from.Hex(), tx.Nonce()))
	if err != nil {
		log.Error("error taking from sender limiter", "err", err, "req_id", GetReqID(ctx))
		return ErrInternal
	}
	if !ok {
		log.Debug("sender rate limit exceeded", "sender", from.Hex(), "req_id", GetReqID(ctx))
		return ErrOverSenderRateLimit
	}

	return nil
}

func (s *Server) isAllowedChainId(chainId *big.Int) bool {
	if s.allowedChainIds == nil || len(s.allowedChainIds) == 0 {
		return true
	}
	for _, id := range s.allowedChainIds {
		if chainId.Cmp(id) == 0 {
			return true
		}
	}
	return false
}

func setCacheHeader(w http.ResponseWriter, cached bool) {
	if cached {
		w.Header().Set(cacheStatusHdr, "HIT")
	} else {
		w.Header().Set(cacheStatusHdr, "MISS")
	}
}

func writeRPCError(ctx context.Context, w http.ResponseWriter, id json.RawMessage, err error) {
	var res *RPCRes
	if r, ok := err.(*RPCErr); ok {
		res = NewRPCErrorRes(id, r)
	} else {
		res = NewRPCErrorRes(id, ErrInternal)
	}
	writeRPCRes(ctx, w, res)
}

func writeRPCRes(ctx context.Context, w http.ResponseWriter, res *RPCRes) {
	statusCode := 200
	if res.IsError() && res.Error.HTTPErrorCode != 0 {
		statusCode = res.Error.HTTPErrorCode
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(statusCode)
	ww := &recordLenWriter{Writer: w}
	enc := json.NewEncoder(ww)
	if err := enc.Encode(res); err != nil {
		log.Error("error writing rpc response", "err", err)
		RecordRPCError(ctx, BackendProxyd, MethodUnknown, err)
		return
	}
	httpResponseCodesTotal.WithLabelValues(strconv.Itoa(statusCode)).Inc()
	RecordResponsePayloadSize(ctx, ww.Len)
}

func writeBatchRPCRes(ctx context.Context, w http.ResponseWriter, res []*RPCRes) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(200)
	ww := &recordLenWriter{Writer: w}
	enc := json.NewEncoder(ww)
	if err := enc.Encode(res); err != nil {
		log.Error("error writing batch rpc response", "err", err)
		RecordRPCError(ctx, BackendProxyd, MethodUnknown, err)
		return
	}
	RecordResponsePayloadSize(ctx, ww.Len)
}

func instrumentedHdlr(h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		respTimer := prometheus.NewTimer(httpRequestDurationSumm)
		h.ServeHTTP(w, r)
		respTimer.ObserveDuration()
	}
}

func GetAuthCtx(ctx context.Context) string {
	authUser, ok := ctx.Value(ContextKeyAuth).(string)
	if !ok {
		return "none"
	}

	return authUser
}

func GetReqID(ctx context.Context) string {
	reqId, ok := ctx.Value(ContextKeyReqID).(string)
	if !ok {
		return ""
	}
	return reqId
}

func GetXForwardedFor(ctx context.Context) string {
	xff, ok := ctx.Value(ContextKeyXForwardedFor).(string)
	if !ok {
		return ""
	}
	return xff
}

type recordLenWriter struct {
	io.Writer
	Len int
}

func (w *recordLenWriter) Write(p []byte) (n int, err error) {
	n, err = w.Writer.Write(p)
	w.Len += n
	return
}

type NoopRPCCache struct{}

func (n *NoopRPCCache) GetRPC(context.Context, *RPCReq) (*RPCRes, error) {
	return nil, nil
}

func (n *NoopRPCCache) PutRPC(context.Context, *RPCReq, *RPCRes) error {
	return nil
}

func truncate(str string, maxLen int) string {
	if maxLen == 0 {
		maxLen = maxRequestBodyLogLen
	}

	if len(str) > maxLen {
		return str[:maxLen] + "..."
	} else {
		return str
	}
}

type batchElem struct {
	Req   *RPCReq
	Index int
}

func createBatchRequest(elems []batchElem) []*RPCReq {
	batch := make([]*RPCReq, len(elems))
	for i := range elems {
		batch[i] = elems[i].Req
	}
	return batch
}
