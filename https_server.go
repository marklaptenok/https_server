package https_server

//	TO-DO: put the code into several .go files.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"codelearning.online/conf"
	"codelearning.online/logger"
)

type Handle struct {
	//	o use in log messages.
	server_id uint8
	//	Server configuration inlucding binding options, timeouts, and other limits.
	cnf conf.ClociConfiguration
	//	The encrypted transport a server uses.
	tls_listener *net.Listener
	//	Allowed TLS protocols.
	tls_protocols []string
	//	The transport a server uses.
	tcp_listener *net.Listener
	//	Set of functions (processors) to process incomming data.
	processors []func(ctx context.Context, message []byte) (context.Context, []byte, error)
	//	To allow thread-safe operation on a server.
	//	For example, to safely stop the server when it receives data from a client.
	syncer sync.Mutex
	//	To report to server's operations that the server is not allowed to work anymore.
	closed chan struct{}
}

var (
	//	Server handles. One handle per each server.
	handles        map[uint8]*Handle
	next_server_id uint8 = 1
	//	Lock to change the handles and 'next_server_id' safely across threads.
	lock sync.Mutex
	//	Pool of readers.
	buffered_readers_pool sync.Pool
)

//	HTTP 1.1 response statuses.
var response_status = struct {
	timeout_hit    string
	shit           string
	internal_error string
	success        string
}{
	timeout_hit:    "409 Conflict",
	shit:           "418 I'm a teapot",
	internal_error: "500 Internal Server Error",
	success:        "200 OK",
}

//	HTTP 1.1 response headers.
var response_headers = struct {
	protocol               string
	content_type_plaintext string
	content_type_json      string
	content_length         string
	date                   string
	connection_close       string
	delimiter              string
}{
	protocol:               "HTTP/1.1 ",
	content_type_plaintext: "Content-Type: text/plain; charset=utf-8",
	content_type_json:      "Content-Type: application/json; charset=utf-8",
	content_length:         "Content-Length: ",
	date:                   "Date: ",
	connection_close:       "Connection: close",
	delimiter:              "\r\n",
}

//	Locks and returns the close status channel (in to-receive-only mode) to caller.
//	It's thread safe. Nobody can write or read to/from the channel until current call is satisfied.
func (server *Handle) get_closed_channel() <-chan struct{} {
	server.syncer.Lock()
	defer server.syncer.Unlock()

	return server.get_closed_channel_locked()
}

//	Returns the close status channel.
func (server *Handle) get_closed_channel_locked() chan struct{} {
	if server.closed == nil {
		server.closed = make(chan struct{})
	}

	return server.closed
}

//	Sends a signal to stop listens for new incomming connections.
//	Has to be called by Stop() only. It's not thread-safe.
func (server *Handle) close_server_channel() {
	closed_channel := server.get_closed_channel_locked()
	select {
	case <-closed_channel:
		//	Already closed. Don't close again.
	default:
		//	close() sends to 0 to unbuffered channel.
		close(closed_channel)
	}
}

/*
type incomingConnectionHandler struct {
	lock               sync.Mutex
	connections_amount uint16
}
*/

//	Reports whether a TLS record header looks like it might've been a misdirected plaintext HTTP request.
//	Taken from https://cs.opensource.google/go/go/+/refs/tags/go1.17.6:src/net/http/server.go
func is_tls_header_looks_like_HTTP(header [5]byte) bool {
	switch string(header[:]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

/*
	Parses "POST /compile HTTP/1.1" into its three parts and checks them according to the rules:
	- only POST requests are accepted;
	- URI has to be equal to 'route' filed of server's configuration;
	- protocol has to equal to "HTTP/1.1" or "HTTP/1.0".
*/
func (server *Handle) check_request_line(line string) error {
	substrings := strings.Split(line, " ")
	if len(substrings) != 3 {
		location, _ := logger.Get_function_name()
		return &logger.ClpError{1, "Misformed HTTP/1.x request", location}
	}
	for _, substring := range substrings {
		if len(substring) == 0 {
			location, _ := logger.Get_function_name()
			return &logger.ClpError{1, "Misformed HTTP/1.x request", location}
		}
	}
	if substrings[0] != "POST" {
		location, _ := logger.Get_function_name()
		substring_length := len(substrings[0])
		if substring_length > 16 {
			substring_length = 16
		}
		return &logger.ClpError{1, "Not the POST method is used (used: " + substrings[0][:substring_length] + ")", location}
	}
	if substrings[1][1:] != server.cnf.Route() {
		location, _ := logger.Get_function_name()
		substring_length := len(substrings[1])
		if substring_length > 64 {
			substring_length = 64
		}
		return &logger.ClpError{1, "Unknown route (given: " + substrings[1][:substring_length] + ")", location}
	}
	if substrings[2] != "HTTP/1.1" && substrings[2] != "HTTP/1.0" {
		location, _ := logger.Get_function_name()
		substring_length := len(substrings[2])
		if substring_length > 16 {
			substring_length = 16
		}
		return &logger.ClpError{1, "Unsupported protocol (given: " + substrings[2][:substring_length] + ")", location}
	}
	return nil
}

//	Gets a buffer from the pools of buffers (bufio.Reader) for reading data from a connection.
//	If the pools are empty, creates new buffer.
func (server *Handle) get_buffered_reader(connection *tls.Conn, size_limit uint64) *bufio.Reader {

	//	If size limit for amount of read bytes is not set, sets it to maximum (= no limit).
	if size_limit == 0 {
		size_limit = 1<<63 - 1
	}
	logger.Debug("Connection %v: size limit to read client's request = %d bytes", connection.RemoteAddr().String(), size_limit)

	//	Creates new bufio reader if the pool is empty.
	item_bufioreader := buffered_readers_pool.Get()
	connection_reader := &connectionReader{
		connection:   connection,
		has_byte:     false,
		is_reading:   false,
		is_aborted:   false,
		remain_bytes: size_limit}

	var reader *bufio.Reader
	if item_bufioreader == nil {
		reader = bufio.NewReader(connection_reader)
	} else {
		reader, _ = item_bufioreader.(*bufio.Reader)
	}
	reader.Reset(connection_reader)

	/*
			TO-DO: delete this.

		//	Creates new text reader based on the bufio reader if the pool is empty.
		item_textreader := textreaders_pool.Get()
		if item_textreader == nil {
			return textproto.NewReader(reader)
		}

		//	Sets underlying bufio reader to the text reader.
		textreader, _ := item_textreader.(*textproto.Reader)
		textreader.R = reader

		return textreader

	*/

	return reader
}

//	Puts the text reader and underlying bufio reader to the related pools.
func (server *Handle) put_buffered_reader(reader *bufio.Reader) {
	buffered_readers_pool.Put(reader)
}

//	Verifies the TLS connection's parameters.
//	TLS handshake has to be already completed.
func (server *Handle) check_tls_connection_parameters(tls_connection *tls.Conn) bool {
	//	Gets the TLS connection's state.
	tls_connection_state := tls_connection.ConnectionState()
	logger.Debug("Server %d: connection %v: connection state: %+v", server.server_id, tls_connection.RemoteAddr().String(), tls_connection_state)

	//	Verifies that the negotiated protocol is what we accept.
	logger.Debug("Server %d: connection %v: negotiated protocol: %v", server.server_id, tls_connection.RemoteAddr().String(), tls_connection_state.NegotiatedProtocol)
	protocol_is_found := false
	for index := range server.tls_protocols {
		if server.tls_protocols[index] == tls_connection_state.NegotiatedProtocol {
			protocol_is_found = true
			break
		}
	}

	//	Checks whether the negotiated protocol is allowed.
	if !protocol_is_found {
		logger.Warning("Server %d: connection %v: negotiated protocol is not allowed: %v", server.server_id, tls_connection.RemoteAddr().String(), tls_connection_state.NegotiatedProtocol)

		return false
	}

	//	 Verifies TLS version. Only versions 1.3 and 1.2 are allowed.
	logger.Debug("Server %d: connection %v: TLS version: %v", server.server_id, tls_connection.RemoteAddr().String(), tls_connection_state.Version)
	if tls_connection_state.Version != tls.VersionTLS12 && tls_connection_state.Version != tls.VersionTLS13 {
		logger.Warning("Server %d: connection %v: TLS version %v is not allowed: %v", server.server_id, tls_connection.RemoteAddr().String(), tls_connection_state.Version)

		return false
	}

	return true
}

//	Reads an HTTP request from the incomming connection 'connection' with the set of processors 'server.processors'.
//	Each processor's output is the input of next processor.
//	Response to the HTTP request is the output of the last processor in the set.
func (server *Handle) process_connection(connection *net.Conn) {

	if server.processors == nil || len(server.processors) == 0 {
		logger.Debug("Server %d: no processor is set", server.server_id)
		return
	}

	logger.Debug("Server %d: starts processing an incomming connection from %s", server.server_id, (*connection).RemoteAddr().String())

	start_processing := time.Now()

	//	In case of an error occurs on the given connection,	logs and closes the connection.
	defer func() {
		if err := recover(); err != nil {
			logger.Warning("Server %d: connection %s will be closed unexpectedly: %v", server.server_id, (*connection).RemoteAddr().String(), err)
		}
		(*connection).Close()
	}()

	//	When processing ends, it will measure the time elapsed for completing the reading.
	defer func() {
		logger.Debug("Server %d: stops processing the incomming connection from %s (time elapsed %v)", server.server_id, (*connection).RemoteAddr().String(), time.Now().Sub(start_processing))
	}()

	//	TO-DO: set different timeouts for reading header and body.

	//	The response for a client has to be write during cnf.write_response_timeout.
	//	Otherwise, the connection will be closed.
	(*connection).SetWriteDeadline(time.Now().Add(server.cnf.Response_write_timeout()))

	//	Checks whether the connections is a TLS connection.
	tls_connection, is_it := (*connection).(*tls.Conn)
	if !is_it {
		logger.Warning("Server %d: connection %v will be closed because it's not a TLS connection", server.server_id, (*connection).RemoteAddr().String())

		(*connection).Close()
		return
	}

	//	Sets timeout for TLS handshake.
	//	This is needed for securiry reasons.
	tls_handshake_ctx, tls_handshake_ctx_cancel_function := context.WithTimeout(context.Background(), server.cnf.TLS_handshake_timeout())
	defer tls_handshake_ctx_cancel_function()

	start := time.Now()
	//	Starts a TLS handshake.
	if err := tls_connection.HandshakeContext(tls_handshake_ctx); err != nil {
		//	Checks whether the handshake failed because it hadn't been a TLS handshake but a simple HTTP initiation.
		//	HTTP connections are prohibited.
		if underlying_connection, ok := err.(tls.RecordHeaderError); ok && underlying_connection.Conn != nil {

			if is_tls_header_looks_like_HTTP(underlying_connection.RecordHeader) {
				io.WriteString(underlying_connection.Conn, "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server. Not allowed\n")

				logger.Debug("Server %d: connection %v will be closed because it's an HTTP connection: %v", server.server_id, tls_connection.RemoteAddr().String(), err)

				underlying_connection.Conn.Close()
				tls_connection.Close()

				return
			}

			logger.Warning("Server %d: connection %v will be closed because of a handshake error: %v", server.server_id, tls_connection.RemoteAddr().String(), err)

			underlying_connection.Conn.Close()
			tls_connection.Close()

			return
		}

		logger.Warning("Server %d: connection %v will be closed because of a handshake error: %v", server.server_id, tls_connection.RemoteAddr().String(), err)

		(*connection).Close()
		tls_connection.Close()

		return
	}
	end := time.Now()

	//	The TLS handshake successfully done.

	logger.Debug("Server %d: connection %v: TLS handshake successfully done (time elapsed %v)", server.server_id, tls_connection.RemoteAddr().String(), end.Sub(start))

	//	Checks the TLS connection parameters (version, protocol, etc.).
	if !server.check_tls_connection_parameters(tls_connection) {
		//	TO-DO: check whether it's not needed here to clean up something.

		(*connection).Close()
		tls_connection.Close()

		return
	}

	//	TLS connections parameters successfully verified.
	logger.Debug("Server %d: connection %v: the TLS parameters are valid", server.server_id, tls_connection.RemoteAddr().String())

	//	Starts reading client's request.

	//	Reads the header.

	//	Prepares a reader from the pool of read buffers.
	//	We don't set a limit to size of read data, because we will not parse the header and just skip it.
	buffered_reader := server.get_buffered_reader(tls_connection, server.cnf.Request_header_size_limit()+server.cnf.Request_body_size_limit())
	defer func() {
		server.put_buffered_reader(buffered_reader)
	}()

	//	The request has to be read during server.cnf.request_read_timeout.
	//	Otherwise, the connection will be closed.
	(*connection).SetReadDeadline(time.Now().Add(server.cnf.Request_read_timeout()))

	//	Reads the first line to check method, URI, and protocol.
	//	In reality, it reads more (e.g. 4096 bytes) which depends on the OS kernel settings regarding the TCP stack.
	//	15 means all symbols in header "POST <route> HTTP/1.x" except the route itself.
	first_line_fragment := make([]byte, 15+len(server.cnf.Route()))
	fisrt_line_fragment_read_bytes_cnt, err := buffered_reader.Read(first_line_fragment)
	if err != nil || fisrt_line_fragment_read_bytes_cnt != 15+len(server.cnf.Route()) {
		logger.Warning("Server %d: connection %v: reading first line failed: %v", server.server_id, tls_connection.RemoteAddr().String(), err)

		(*connection).Close()
		tls_connection.Close()

		return
	}

	//	First after reading, cuts all unmeaningful symbols (= zeroes), if they are.
	first_line_fragment = bytes.Trim(first_line_fragment, "\x00")

	logger.Debug("Server %d: connection %v: first line of the request \"%s\"", server.server_id, tls_connection.RemoteAddr().String(), first_line_fragment)

	//	Checks the first line.
	//	If the first line is invalid, closes the connection.
	if err := server.check_request_line(string(first_line_fragment)); err != nil {
		logger.Warning("Server %d: connection %v: first line is invalid: %v", server.server_id, tls_connection.RemoteAddr().String(), err)

		(*connection).Close()
		tls_connection.Close()

		return
	}
	logger.Debug("Server %d: connection %v: first line is valid", server.server_id, tls_connection.RemoteAddr().String())

	/*
		TO-DO:
			read the header by chunks of server.cnf.request_header_size_limit + server.cnf.request_body_size_limit/ 100 * 5.
			collect the chunks into a string (or []bytes).
			search '\r\n\r\n' in the string from its end.
			check size of the final string on each reading. If it's greater then server.cnf.request_header_size_limit, then
				stop because of hit the limit
			if the sequence found, then rewrite the string by having only part that is after the sequence. We don't need the header.
			keep reading
			check size of the final string on each reading. If it's greater then server.cnf.request_body_size_limit, then
				stop because of hit the limit
			when the timeout reaches and read bytes count is equal to 0, stops reading.
			lauch the processor

			use connectionReader to check EOF and size limit. Do not do this here!

	*/

	//	Sets initial size of the read-request-body-buffer to 1% of
	//	server.cnf.request_header_size_limit + server.cnf.request_body_size_limit,
	//	but not less than 1 byte.
	current_buffer_size := (server.cnf.Request_header_size_limit() + server.cnf.Request_body_size_limit()) / 100
	if current_buffer_size == 0 {
		current_buffer_size = 1
	}
	logger.Debug("Server %d: connection %v: buffer size for reading = %d bytes", server.server_id, tls_connection.RemoteAddr().String(), current_buffer_size)

	//	Starts reading the whole packet until 'read_bytes_cnt' exceeds the 'limit'.
	read_bytes_cnt := uint64(0)
	limit := server.cnf.Request_header_size_limit()
	limit_name := "header"
	var packet []byte
	var delimeter = []byte{'\r', '\n', '\r', '\n'}
	for {

		//	Prepares a buffer to place data sent by the client.
		buffer := make([]byte, current_buffer_size)

		//	Reads data from the connection.
		currently_read_bytes_cnt, err := buffered_reader.Read(buffer)
		if err != nil {
			//	If the request is empty or the reader approached the end of the request, stops reading.
			if err == io.EOF {

				if currently_read_bytes_cnt > 0 {

					//	Cuts out possible zeroes.
					buffer = bytes.Trim(buffer, "\x00")

					//	Adds the read fragment to the read data.
					packet = append(packet, buffer...)

				} else {

					break

				}

			} else {

				//	In case any other error, for example when reader's limit for the amount of read bytes,
				//	closes the incomming connection immediately.
				logger.Warning("Server %d: connection %v: reading request failed: %v", server.server_id, tls_connection.RemoteAddr().String(), err)

				(*connection).Close()
				tls_connection.Close()

				return

			}
		}

		//	Increases the amount of read bytes.
		read_bytes_cnt += uint64(currently_read_bytes_cnt)

		//	Checks we have not hit the request header size limit.
		//	If so, close the incoming connection immediately.
		if read_bytes_cnt > limit {

			logger.Warning("Server %d: connection %v: request %s size has reached the limit (read %d bytes, limit %d bytes)", server.server_id, tls_connection.RemoteAddr().String(), limit_name, read_bytes_cnt, limit)

			(*connection).Close()
			tls_connection.Close()

			return
		}

		//	Cuts out possible zeroes.
		buffer = bytes.Trim(buffer, "\x00")

		//	Adds the read fragment to the read data.
		packet = append(packet, buffer...)

		//	Checks whether we have reached the end of HTTP/1.x section (header, body).
		//	Stops when recognises an "\r\n\r\n" sequence which means the end of HTTP/1.x section.
		if last_index := bytes.LastIndex(packet, delimeter); last_index != -1 {
			if first_index := bytes.Index(packet, delimeter); last_index == first_index {
				//	We have reached the end of the header. Let's store only the part of 'packet'
				//	which is a part of the body.
				packet = packet[last_index+len(delimeter):]

				logger.Debug("Server %d: connection %v: header successfully skipped (it's size = %d bytes)", server.server_id, tls_connection.RemoteAddr().String(), read_bytes_cnt-uint64(len(packet)))

				//	Prepares the variables to control the size of the body which will be started to read.
				read_bytes_cnt = 0
				limit = server.cnf.Request_body_size_limit()
				limit_name = "body"
			} else {
				//	The body so short that it's comprised in the 'packet'.
				//	So, nothing to read more. Stops reading.
				packet = packet[first_index+len(delimeter) : last_index]
				break
			}
		}
	}
	logger.Debug("Server %d: connection %v: body successfully read (it's size = %d bytes)\n===== body start =====\n%s\n===== body end =====\n", server.server_id, tls_connection.RemoteAddr().String(), len(packet), packet)

	//	If request's body is empty, sends back a normal HTTP response and terminates the connection.
	if len(packet) == 0 {

		fmt.Fprintf(tls_connection,
			response_headers.protocol+
				response_status.shit+
				response_headers.delimiter+
				response_headers.content_type_plaintext+
				response_headers.delimiter+
				response_headers.connection_close+
				response_headers.delimiter+
				response_headers.delimiter+
				response_status.shit+
				response_headers.delimiter)

		(*connection).Close()
		tls_connection.Close()

		return
	}

	/*
		TO-DO: check that the connection is still opened, run a thread to check it realtime,
		and send a new context to each processor, so when the client closes the connection,
		we can cancel processing immediately. This context has to be created at the beginning
		of this function along with the a thread that checks connection's state.
		If the client closes his end of the socket, we have to abotr any processing
		of its request immediately.
	*/
	//	Whole processing of the client's request has to happen without the certain period ('server.cnf.timeout').
	//	Otherwise, the request is considered unreposnded and the server responses with an error code, and
	//	closes the connection.
	ctx, request_context_cancel_func := context.WithTimeout(context.Background(), server.cnf.Timeout())
	defer request_context_cancel_func()

	//	Processes the body.
	var result []byte = nil
	err = nil
	for _, processor := range server.processors {

		if err != nil || ctx == nil {
			if ctx != nil {
				ctx.Done()
			}
			break
		}

		if result == nil {
			ctx, result, err = processor(ctx, packet)
			continue
		}

		//	Each processor passes to next processor in the chain ('processors')
		//	the result of the current processor and its context (which can be adjusted or remained unchanged).
		ctx, result, err = processor(ctx, result)
	}

	//	Checks whether processing has been succeeded or not.
	if err != nil {

		logger.Warning("Server %d: connection %v: processor pipeline failed: %s", server.server_id, tls_connection.RemoteAddr().String(), err.Error())

		var status = response_status.internal_error
		var message = response_status.internal_error

		//	Sends the report of server's error and willingness to close the connection.

		if cloci_err, is_clp_error := err.(*logger.ClpError); is_clp_error {

			switch cloci_err.Code {
			//	Building timeout has been hit.
			case 8:
				status = response_status.timeout_hit
				message = "{\n\t\"error\":41\n}"
			//	Running the built application timeout has been hit.
			case 14:
				status = response_status.timeout_hit
				message = "{\n\t\"error\":42\n}"
			default:
				logger.Info("Server %d: connection %v: unprocessed CLP error with code: %d", server.server_id, tls_connection.RemoteAddr().String(), cloci_err.Code)
			}

		}

		//	Sends response with an error prepared above.
		//	If none of the cases above have been fulfilled, the general error will be sent.
		fmt.Fprintf(tls_connection,
			response_headers.protocol+
				status+
				response_headers.delimiter+
				response_headers.content_type_plaintext+
				response_headers.delimiter+
				response_headers.connection_close+
				response_headers.delimiter+
				response_headers.delimiter+
				message+
				response_headers.delimiter)

	} else {

		if result != nil {

			logger.Debug("Server %d: connection %v: request successfully processed (response size = %d bytes)\n===== response body start =====\n%s\n===== response body end =====\n", server.server_id, tls_connection.RemoteAddr().String(), len(result), result)

			fmt.Fprintf(tls_connection,
				response_headers.protocol+
					response_status.success+
					response_headers.delimiter+
					response_headers.date+time.Now().Format(http.TimeFormat)+
					response_headers.delimiter+
					response_headers.content_type_json+
					response_headers.delimiter+
					response_headers.content_length+strconv.FormatInt(int64(len(result)+4), 10)+
					response_headers.delimiter+
					response_headers.connection_close+
					response_headers.delimiter+
					response_headers.delimiter+
					string(result)+
					response_headers.delimiter+
					response_headers.delimiter)

		} else {

			logger.Warning("Server %d: connection %v: response is not provided", server.server_id, tls_connection.RemoteAddr().String())

		}

	}

	(*connection).Close()
	tls_connection.Close()
}

//	Starts a loop to accept incomming connections.
func (server *Handle) serve(listener *net.Listener) error {

	for {
		logger.Debug("Server %d: has started accepting new connections", server.server_id)
		connection, err_ext := (*listener).Accept()
		logger.Debug("Server %d: Accept() has unblocked", server.server_id)

		//	How long to sleep on accept failure.
		delay := 5 * time.Millisecond
		if err_ext != nil {
			//	Checks whether the server was closed. So, this has caused the error.
			select {
			case <-server.get_closed_channel():
				if location, err := logger.Get_function_name(); err != nil {
					return &logger.ClpError{
						Code:     uint16(server.server_id),
						Msg:      "Server is closed",
						Location: location}
				} else {
					return &logger.ClpError{
						Code:     uint16(server.server_id),
						Msg:      "Server is closed",
						Location: ""}
				}
			default:
			}

			//	Checks whether the error during acception is temporary or not.
			//	If so, we will wait and try to accept again.
			//	Starts waiting with 5 msec, then increases twice up to 500 msec.
			if network_error, ok := err_ext.(net.Error); ok && network_error.Temporary() {
				if max := 500 * time.Millisecond; delay > max {
					delay = max
				}

				logger.Info("Accept error: %v; retrying in %v", network_error, delay)
				time.Sleep(delay)

				delay *= 2
				continue
			}
			//	If error is not temporary, then returns.
			logger.Warning("Accept error: %v", err_ext)
			if location, err := logger.Get_function_name(); err != nil {
				return &logger.ClpError{
					Code:     uint16(server.server_id),
					Msg:      "Accept failed: " + err_ext.Error(),
					Location: location}
			} else {
				return &logger.ClpError{
					Code:     uint16(server.server_id),
					Msg:      "Accept failed: " + err_ext.Error(),
					Location: ""}
			}
		}

		logger.Info("Server %d: new incomming connection from %s", server.server_id, connection.RemoteAddr().String())
		go server.process_connection(&connection)
	}
}

/*
	Returns free server id. Allocates the server handles storage is its needed.
	Maximum allowed amount of simultaneously working servers is 254.

	The function is thread safe if you would like to start several servers simultaneously.
*/
func get_server_id() (uint8, error) {

	lock.Lock()
	defer lock.Unlock()

	//	Allocates the handle storage to store handles of servers if it hasn't been done yet.
	if handles == nil {
		handles = make(map[uint8]*Handle)
		logger.Debug("Handle storage has been allocated")
	} else if len(handles) == 254 {
		location, _ := logger.Get_function_name()
		return 0, &logger.ClpError{
			Code:     1,
			Msg:      "Can't start new server. The limit has been reached",
			Location: location}
	}

	//	Finds an empty id for new server.
	//	Returns with error if the limit of 254 servers reached.
	for _, is_found := handles[next_server_id]; is_found == true; _, is_found = handles[next_server_id] {
		if next_server_id == 255 {
			next_server_id = 0
		}
		next_server_id++
	}

	logger.Debug("Id %d has been chosen for new server", next_server_id)

	return next_server_id, nil
}

/*
	Starts new server with the given configuration ('cnf') and set of functions (= processors)
	which will process clients' requests ('pcrs').

	If the processors are not set (= nil), then the server will respond with an 5xx HTTP error message to each request.

	In case of error, returns (nil, *ClpError).

	It's thread safe.
*/
func Start(cnf *conf.ClociConfiguration, pcrs []func(ctx context.Context, message []byte) (context.Context, []byte, error)) (*Handle, error) {

	//	Gets new server ID (is there is a free one). Otherwise, returns the error.
	server_id, err := get_server_id()
	if err != nil {
		return nil, err
	}

	//	Generates a pair of self-signed ED25519 certificates for TLS connection.
	//	It works with curl, wget, etc. This will be used first for performing a TLS handshake.
	certificate_ed25519_pem, private_key_ed25519_pem, err_ext := generate_server_ed25519_certificates(cnf.Bind_address(), "", server_id)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, &logger.ClpError{
			Code:     1,
			Msg:      "PEM encoded ED25519 certificate generating failed: " + err_ext.Error(),
			Location: location}
	}

	//	Creates a ED25519 Certificate from the PEM encoded parts.
	certificate_ed25519, err_ext := tls.X509KeyPair(certificate_ed25519_pem, private_key_ed25519_pem)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, &logger.ClpError{
			Code:     2,
			Msg:      "ED25519 Certificate generating failed: " + err_ext.Error(),
			Location: location}
	}

	//	Generates a pair of self-signed RSA certificates for TLS connection.
	//	It's neeeded for Firefox, Chrome, etc. This will be used second for performing a TLS handshake.
	//	See https://security.stackexchange.com/questions/236931/whats-the-deal-with-x25519-support-in-chrome-firefox
	certificate_rsa_pem, private_key_rsa_pem, err_ext := generate_server_rsa_certificates(cnf.Bind_address(), "", server_id)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, &logger.ClpError{
			Code:     3,
			Msg:      "PEM encoded RSA certificate generating failed: " + err_ext.Error(),
			Location: location}
	}

	//	Creates an RSA Certificate from the PEM encoded parts.
	certificate_rsa, err_ext := tls.X509KeyPair(certificate_rsa_pem, private_key_rsa_pem)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, &logger.ClpError{
			Code:     4,
			Msg:      "RSA Certificate generating failed: " + err_ext.Error(),
			Location: location}
	}

	//	Prepares a TLS configuration.
	//	- puts the certificate to the TLS configuration.
	//	- adds allowed protocols (HTTP/1.1 and HTTP/1.0 are allowed only)
	protocols := make([]string, 2)
	protocols = append(protocols, "http/1.1", "http/1.0")
	tls_cfg := &tls.Config{
		Certificates: []tls.Certificate{certificate_ed25519, certificate_rsa},
		NextProtos:   protocols,
	}

	//	Binds to given IPv4 address (usually in format 127.0.0.1:<port>) e.g. creates a TCP listener.
	host := cnf.Bind_address().String() + ":" + strconv.FormatUint(uint64(cnf.Bind_port()), 10)
	tcp_listener, err_ext := net.Listen("tcp", host)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, &logger.ClpError{
			Code:     5,
			Msg:      "Binding to address " + cnf.Bind_address().String() + " failed: " + err_ext.Error(),
			Location: location}
	}
	logger.Debug("Server %d: binding to address "+cnf.Bind_address().String()+" was successful", server_id)

	//	Creates a TLS listener (= a TLS transport).
	tls_listener := tls.NewListener(tcp_listener, tls_cfg)

	//	Locks the handles storage.
	lock.Lock()
	defer lock.Unlock()

	//	Puts handle of new server to the handles storage.
	handles[server_id] = &Handle{
		server_id:     server_id,
		cnf:           *cnf,
		tls_listener:  &tls_listener,
		tls_protocols: protocols,
		tcp_listener:  &tcp_listener,
		processors:    pcrs,
	}
	logger.Info("Server %d has been started", handles[server_id].server_id)
	logger.Debug("Server's %d configuration: {%+v}", handles[server_id].server_id, handles[server_id].cnf)

	//	Starts the TLS server.
	go handles[server_id].serve(&tls_listener)

	//	Returns handle of the created server to user.
	return handles[server_id], nil
}

//	Stops the server.
//	TO-DO: gracefully shutdown the server.
func (server *Handle) Stop() {
	server.syncer.Lock()
	defer server.syncer.Unlock()

	server.close_server_channel()

	err := (*server.tls_listener).Close()
	logger.Debug("Server %d: TLS transport is closed: %v", server.server_id, err)
	err = (*server.tcp_listener).Close()
	logger.Debug("Server %d: TCP transport is closed: %s", server.server_id, err)

	//	TO-DO: close all opened connections.
	/*
		for c := range srv.activeConn {
			c.rwc.Close()
			delete(srv.activeConn, c)
		}
	*/

	delete(handles, server.server_id)

	logger.Info("Server %d is stopped", server.server_id)
}
