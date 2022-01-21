package https_server

//	TO-DO: put the code into several .go files.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"codelearning.online/conf"
	"codelearning.online/logger"
)

type Handle struct {
	server_id    uint8
	cnf          conf.ClociConfiguration
	tls_listener *net.Listener
	tcp_listener *net.Listener
	syncer       sync.Mutex
	closed       chan struct{}
}

/*
type incomingConnectionHandler struct {
	lock               sync.Mutex
	connections_amount uint16
}
*/
var (
	handles        map[uint8]*Handle
	next_server_id uint8 = 1
)

/*
//	Incoming connections handler
func (this *incomingConnectionHandler) ServeHTTP(response *http.ResponseWriter, request *http.Request) {

	this.lock.Lock()
	defer this.lock.Unlock()

	logger.Info(request.Host)
	logger.Info(request.RemoteAddr)
	logger.Info(request.Method)

	if body, err := io.ReadAll(request.Body); err != nil {
		logger.Warning(err.Error())
		return
	}
	logger.Info(string(body))

	connections_amount++
}

func process_connection_state(connection net.Conn, state ConnState) {

	logger.Debug("%s has reported state %d", connection.RemoteAddr.String(), state)

}
*/

/*
	Generates a key pair of self-signed X.509 ED25519 certificates for a TLS server (with the specified IP address) and
	writes them to the specified folder using server ID as a part of certificate's filename.

	if the path to folder is empty, then returns certificates as []bytes: both PEM ecncoded certificate and private key.

	Based on https://go.dev/src/crypto/tls/generate_cert.go
*/
func generate_server_certificates(bind_address net.IP, path_to_certificates_folder string, server_id uint8) ([]byte, []byte, error) {

	//	Generates a ED25519 key that will be used as a private key.
	_, private_key, err_ext := ed25519.GenerateKey(rand.Reader)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{1, "Can't generate a private key: " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{1, "Can't generate a private key" + err_ext.Error(), ""}
		}
	}

	//	Prepares digital signature bits.
	key_usage := x509.KeyUsageDigitalSignature

	//	Prepares validity dates. The certificate is valid for one year.
	valid_from := time.Now()
	valid_to := valid_from.Add(365 * 24 * time.Hour)

	//	Generates a serial number.
	serial_number_limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial_number, err_ext := rand.Int(rand.Reader, serial_number_limit)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{2, "Failed to generate serial number: " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{2, "Failed to generate serial number: " + err_ext.Error(), ""}
		}
	}

	//	Creates the template for the certificate.
	template := x509.Certificate{
		SerialNumber: serial_number,
		Subject: pkix.Name{
			Organization: []string{"Codelearning.online"},
		},
		NotBefore: valid_from,
		NotAfter:  valid_to,

		KeyUsage:              key_usage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	template.IPAddresses = append(template.IPAddresses, bind_address)

	//	Generates the certificate.
	certificate, err_ext := x509.CreateCertificate(rand.Reader, &template, &template, private_key.Public(), private_key)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{3, "Failed to create certificate: " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{3, "Failed to create certificate: " + err_ext.Error(), ""}
		}
	}

	//	Returns certificates if the path to folder is empty.
	if path_to_certificates_folder == "" {

		//	Marshals the private key.
		private_key_bytes, err_ext := x509.MarshalPKCS8PrivateKey(private_key)
		if err_ext != nil {
			if location, err := logger.Get_function_name(); err != nil {
				return nil, nil, &logger.ClpError{8, "Unable to marshal private key: " + err_ext.Error(), location}
			} else {
				return nil, nil, &logger.ClpError{8, "Unable to marshal private key: " + err_ext.Error(), ""}
			}
		}

		//	Encodes the private key into PEM format.
		private_key_pem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private_key_bytes})
		if private_key_pem == nil {
			if location, err := logger.Get_function_name(); err != nil {
				return nil, nil, &logger.ClpError{11, "Failed to encode certificate to PEM", location}
			} else {
				return nil, nil, &logger.ClpError{11, "UFailed to encode certificate to PEM", ""}
			}
		}

		//	Encodes the cerificate into PEM format.
		certificate_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
		if certificate_pem == nil {
			if location, err := logger.Get_function_name(); err != nil {
				return nil, nil, &logger.ClpError{11, "Failed to encode certificate to PEM", location}
			} else {
				return nil, nil, &logger.ClpError{11, "Failed to encode certificate to PEM", ""}
			}
		}

		return certificate_pem, private_key_pem, nil
	}

	certificate_full_path := path_to_certificates_folder + "/" + strconv.FormatUint(uint64(server_id), 10) + ".pem"

	//	Creates a file in filesystem.
	file, err_ext := os.Create(certificate_full_path)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{4, "Failed to create " + certificate_full_path + ": " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{4, "Failed to create " + certificate_full_path + ": " + err_ext.Error(), ""}
		}
	}

	//	Writes the certificate to the file.
	if err_ext := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certificate}); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{5, "Failed to open " + certificate_full_path + " for writing: " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{5, "Failed to open " + certificate_full_path + " for writing: " + err_ext.Error(), ""}
		}
	}

	//	Closes the file.
	if err_ext := file.Close(); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{6, "Error closing " + certificate_full_path + ": " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{6, "Error closing " + certificate_full_path + ": " + err_ext.Error(), ""}
		}
	}
	logger.Debug("%s is written", certificate_full_path)

	private_key_full_path := path_to_certificates_folder + "/" + strconv.FormatUint(uint64(server_id), 10) + "_key.pem"

	//	Creates and opens a file for writing the private key.
	private_key_file, err_ext := os.OpenFile(private_key_full_path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{7, "Failed to open " + private_key_full_path + " for writing: " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{7, "Failed to open " + private_key_full_path + " for writing: " + err_ext.Error(), ""}
		}
	}

	//	Marshals the private key.
	private_key_bytes, err_ext := x509.MarshalPKCS8PrivateKey(private_key)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{8, "Unable to marshal private key: " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{8, "Unable to marshal private key: " + err_ext.Error(), ""}
		}
	}

	//	Writes the private key to the file.
	if err_ext := pem.Encode(private_key_file, &pem.Block{Type: "PRIVATE KEY", Bytes: private_key_bytes}); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{9, "Failed to write data to " + private_key_full_path + ": " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{9, "Failed to write data to " + private_key_full_path + ": " + err_ext.Error(), ""}
		}
	}

	//	Closes the file with the private key.
	if err_ext := private_key_file.Close(); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, nil, &logger.ClpError{10, "Error closing " + private_key_full_path + ": " + err_ext.Error(), location}
		} else {
			return nil, nil, &logger.ClpError{10, "Error closing " + private_key_full_path + ": " + err_ext.Error(), ""}
		}
	}
	logger.Debug("%s is written", private_key_full_path)

	return nil, nil, nil
}

//	Locks and returns the channel with server close status to caller to receive only.
//	It's thread safe. Nobody can write or read to/from the channel until current call is satisfied.
func (server *Handle) get_closed_channel() <-chan struct{} {
	server.syncer.Lock()
	defer server.syncer.Unlock()

	return server.get_closed_channel_locked()
}

//	Returns the channel with server close status.
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

func process_connection(connection *net.Conn) {
	logger.Debug("Starts processing incomming connection from %s", (*connection).RemoteAddr().String())

	//	TO-DO: add the logic.
	//(*connection).Close()

	logger.Debug("Stops processing incomming connection from %s", (*connection).RemoteAddr().String())
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
					return &logger.ClpError{uint16(server.server_id), "Server is closed", location}
				} else {
					return &logger.ClpError{uint16(server.server_id), "Server is closed", ""}
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
				return &logger.ClpError{uint16(server.server_id), "Accept failed: " + err_ext.Error(), location}
			} else {
				return &logger.ClpError{uint16(server.server_id), "Accept failed: " + err_ext.Error(), ""}
			}
		}

		logger.Info("Server %d: new incomming connection from %s", server.server_id, connection.RemoteAddr().String())
		go process_connection(&connection)
	}
}

//	Starts new server with the given configuration ('cnf').
//	In case of error, returns (nil, *ClpError).
func Start(cnf *conf.ClociConfiguration) (*Handle, error) {

	if handles == nil {
		handles = make(map[uint8]*Handle)
		logger.Debug("Handle storage has been allocated")
	} else if len(handles) == 254 {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, &logger.ClpError{1, "Can't start new server. The limit has been reached", location}
		} else {
			return nil, &logger.ClpError{1, "Can't start new server. The limit has been reached", ""}
		}
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

	//	Generates a pair of certificates for TLS connection.
	certificate_pem, private_key_pem, err_ext := generate_server_certificates(cnf.Bind_address(), "", next_server_id)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, &logger.ClpError{2, "PEM encoded certificate generating failed: " + err_ext.Error(), location}
		} else {
			return nil, &logger.ClpError{2, "PEM encoded certificate generating failed: " + err_ext.Error(), ""}
		}
	}

	//	Creates Certificate from the PEM encoded parts.
	certificate, err_ext := tls.X509KeyPair(certificate_pem, private_key_pem)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, &logger.ClpError{3, "Certificate generating failed: " + err_ext.Error(), location}
		} else {
			return nil, &logger.ClpError{3, "Certificate generating failed: " + err_ext.Error(), ""}
		}
	}

	//	Prepares s TLS configuration.
	//	- puts the certificate to the TLS configuration.
	//	- adds allowed protocols
	protocols := make([]string, 2)
	protocols = append(protocols, "h2", "http/1.1")
	tls_cfg := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   protocols,
	}

	//	Binds to given IPv4 address (usually 127.0.0.1:<port>) e.g. creates a TCP listener.
	host := cnf.Bind_address().String() + ":" + strconv.FormatUint(uint64(cnf.Bind_port()), 10)
	tcp_listener, err_ext := net.Listen("tcp", host)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, &logger.ClpError{4, "Binding to address " + cnf.Bind_address().String() + " failed: " + err_ext.Error(), location}
		} else {
			return nil, &logger.ClpError{4, "Binding to address " + cnf.Bind_address().String() + " failed: " + err_ext.Error(), ""}
		}
	}
	logger.Debug("Server %d: binding to address "+cnf.Bind_address().String()+" was successful", next_server_id)

	//	Creates a TLS listener (= a TLS transport).
	tls_listener := tls.NewListener(tcp_listener, tls_cfg)

	//	Puts handle of new server to the handles storage.
	handles[next_server_id] = &Handle{
		server_id:    next_server_id,
		cnf:          *cnf,
		tls_listener: &tls_listener,
		tcp_listener: &tcp_listener,
	}
	logger.Info("Server %d has been started", handles[next_server_id].server_id)
	logger.Debug("Server %d configuration: {%+v}", handles[next_server_id].server_id, handles[next_server_id].cnf)

	//	Starts the TLS server.
	go handles[next_server_id].serve(&tls_listener)

	//	Returns handle of the created server to user.
	return handles[next_server_id], nil
}

//	Stops the server.
//	TO-DO: gracefully shutdown the server.
func (server *Handle) Stop() {
	server.syncer.Lock()
	defer server.syncer.Unlock()

	server.close_server_channel()

	(*server.tls_listener).Close()
	(*server.tcp_listener).Close()

	//	TO-DO: close all opened connections.
	/*
		for c := range srv.activeConn {
			c.rwc.Close()
			delete(srv.activeConn, c)
		}
	*/

	//	TO-DO: remove the server data from handles.
	logger.Info("Server %d is stopped", server.server_id)
}
