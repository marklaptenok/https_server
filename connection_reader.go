package https_server

import (
	"crypto/tls"
	"io"
	"sync"
	"time"

	"codelearning.online/logger"
)

type connectionReader struct {
	connection *tls.Conn

	guard        sync.Mutex
	has_byte     bool
	read_buffer  [1]byte
	condition    *sync.Cond
	is_reading   bool
	is_aborted   bool
	remain_bytes uint64
}

//	Locks the reader.
func (reader *connectionReader) lock() {
	reader.guard.Lock()
	if reader.condition == nil {
		reader.condition = sync.NewCond(&reader.guard)
	}
}

//	Unlocks the reader.
func (reader *connectionReader) unlock() {
	reader.guard.Unlock()
}

/*
func (reader *connectionReader) start_background_read() {
	reader.lock()
	defer reader.unlock()

	//	If erading is occurs (for somehow), stops the service immediately.
	if reader.is_reading {
		location, _ := logger.Get_function_name()
		logger.Error(
			&logger.ClpError{
				Code:     1,
				Msg:      "Concurent reading from HTTP request",
				Location: location})
	}

	//	Does not start reading if we have not been processed a byte that had been read.
	if reader.has_byte {
		return
	}

	//	Sets the status that we have started reading.
	reader.is_reading = true

	//	Sets no timeout.
	reader.connection.SetReadDeadline(time.Time{})

	//	Starts reading in background, so reading can't block.
	go reader.read_in_background()
}

//	Reads data from the connection.
func (reader *connectionReader) read_in_background() {
	//	Reads one byte from the connection.
	//	If it blocks because of the peer can't (or don't want to) send data to the server,
	//	we will not care.
	amount_of_read_bytes, err := reader.connection.Read(reader.read_buffer[:])

	reader.lock()

	if amount_of_read_bytes == 1 {
		reader.has_byte = true
	}

	if network_error, ok := err.(net.Error); ok && reader.is_aborted && network_error.Timeout() {
		//	Does nothing. It's the expected error from another thread calling abort_pending_read().
	} else if err != nil {
		reader.handle_read_error(err)
	}

	reader.is_aborted = false
	reader.is_reading = false

	reader.unlock()

	//	Continues all threads working with this connection.
	reader.condition.Broadcast()
}

//	Aborts reading when it stalls.
func (reader *connectionReader) abort_pending_read() {
	reader.lock()
	defer reader.unlock()

	//	If reading doesn't occure, nothing to abort. So, does nothing.
	if !reader.is_reading {
		return
	}

	reader.is_aborted = true

	//	Cancels reading immeditelly. It's needed if reading is in progress but blocks
	//	(= has became pending).
	//	So, if read_in_background() is blocked on reading (at the first instruction), unblocks it.
	reader.connection.SetReadDeadline(time.Unix(1, 0))

	//	Wants until all reading operations finish (read_in_background() returns).
	for reader.is_reading {
		reader.condition.Wait()
	}

	//	Restores the timeout (which is no timeout) for the connection.
	reader.connection.SetReadDeadline(time.Time{})
}

func (reader *connectionReader) set_read_bytes_limit(remain_bytes uint64) {
	reader.remain_bytes = remain_bytes
}
*/
func (reader *connectionReader) is_read_bytes_limit_hit() bool {
	return reader.remain_bytes == 0
}

func (reader *connectionReader) handle_read_error(err error) {
	logger.Debug("Connection %s: reading error: %v", reader.connection.RemoteAddr().String(), err)

	reader.notify_peer_that_connection_is_closed()
}

func (reader *connectionReader) notify_peer_that_connection_is_closed() {
	//	TO-DO:
	/*
		res, _ := cr.conn.curReq.Load().(*response)
		if res != nil && atomic.CompareAndSwapInt32(&res.didCloseNotify, 0, 1) {
			res.closeNotifyCh <- true
		}
	*/
}

//	This functions is needed to make connectionReader based on io.LimitedReader.
//	See https://pkg.go.dev/io#LimitedReader.Read
func (reader *connectionReader) Read(p []byte) (n int, err error) {
	reader.lock()

	logger.Debug("Connection %v: reader's buffer length = %d bytes", reader.connection.RemoteAddr().String(), len(p))

	//	Checks that reading of this connection is monopolistic.
	if reader.is_reading {

		reader.unlock()

		location, _ := logger.Get_function_name()
		logger.Error(
			&logger.ClpError{
				Code:     1,
				Msg:      "there is another reader",
				Location: location})

	}

	//	Checks whether we have reached the limit of data to read out or not.
	if reader.is_read_bytes_limit_hit() {

		reader.unlock()

		location, _ := logger.Get_function_name()
		return -1, &logger.ClpError{
			Code:     2,
			Msg:      "reading limit has been hit",
			Location: location}

	}

	//	If given buffer is empty, nothing we can do.
	if len(p) == 0 {
		reader.unlock()

		logger.Debug("Connection %v: provided buffer for reading is empty", reader.connection.RemoteAddr().String())
		return 0, nil
	}

	//	If given buffer is greater, then the current value of the reading limit, adjusts size of the buffer.
	if uint64(len(p)) > reader.remain_bytes {

		p = p[:reader.remain_bytes]

		logger.Debug("Connection %v: provided buffer size adjusted to %d bytes", reader.connection.RemoteAddr().String(), reader.remain_bytes)

	}

	/*
		//	If a byte was read, puts it to the buffer.
		if reader.has_byte {

			p[0] = reader.read_buffer[0]
			reader.has_byte = false

			reader.unlock()

			return 1, nil
		}
	*/

	reader.is_reading = true

	//	Unlock this connectionReader to prevent blocking from the following connection.Read()
	reader.unlock()

	//	Reads data from the connection.
	//	Warning! Read timeout has to be set for the connection in prior.
	start := time.Now()
	n, err = reader.connection.Read(p)
	logger.Debug("Connection %v: end reading (read %d bytes, time elapsed %v)", reader.connection.RemoteAddr().String(), n, time.Now().Sub(start))

	reader.lock()

	reader.is_reading = false

	//	If reading was aborted, checks the reason for that.
	if err != nil {
		//	If some data has been read, it's because of some different error than the timeout hit.
		if n > 0 {

			reader.handle_read_error(err)

			location, _ := logger.Get_function_name()
			return n, &logger.ClpError{
				Code:     3,
				Msg:      "underlying connection error: " + err.Error(),
				Location: location}

		} else {
			//	It's because the timeout hit. So, returns with io.EOF.
			return n, io.EOF
		}
	}

	if uint64(n) >= reader.remain_bytes {
		reader.remain_bytes = 0
	} else {
		reader.remain_bytes -= uint64(n)
	}
	reader.unlock()

	reader.condition.Broadcast()

	return n, nil
}
