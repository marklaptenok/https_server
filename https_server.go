package https_server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	"codelearning.online/conf"
	"codelearning.online/logger"
)

type Handle struct {
	server_id uint8
	cnf       conf.ClociConfiguration
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

//	Generates a key pair of self-signed X.509 ED25519 certificates for a TLS server (with the specified IP address) and
//	writes them to the specified folder using server ID as a part of certificate's filename.
//	Based on https://go.dev/src/crypto/tls/generate_cert.go
func generate_server_certificates(bind_address net.IP, path_to_certificates_folder string, server_id uint8) error {

	//	Generates a ED25519 key that will be used as a private key.
	_, private_key, err_ext := ed25519.GenerateKey(rand.Reader)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{1, "Can't generate a private key: " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{1, "Can't generate a private key" + err_ext.Error(), ""}
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
			return &logger.ClpError{2, "Failed to generate serial number: " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{2, "Failed to generate serial number: " + err_ext.Error(), ""}
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
			return &logger.ClpError{3, "Failed to create certificate: " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{3, "Failed to create certificate: " + err_ext.Error(), ""}
		}
	}

	certificate_full_path := path_to_certificates_folder + "/" + strconv.FormatUint(uint64(server_id), 10) + ".pem"

	//	Creates a file in filesystem.
	file, err_ext := os.Create(certificate_full_path)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{4, "Failed to create " + certificate_full_path + ": " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{4, "Failed to create " + certificate_full_path + ": " + err_ext.Error(), ""}
		}
	}

	//	Writes the certificate to the file.
	if err_ext := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certificate}); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{5, "Failed to open " + certificate_full_path + " for writing: " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{5, "Failed to open " + certificate_full_path + " for writing: " + err_ext.Error(), ""}
		}
	}

	//	Closes the file.
	if err_ext := file.Close(); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{6, "Error closing " + certificate_full_path + ": " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{6, "Error closing " + certificate_full_path + ": " + err_ext.Error(), ""}
		}
	}
	logger.Debug("%s is written", certificate_full_path)

	private_key_full_path := path_to_certificates_folder + "/" + strconv.FormatUint(uint64(server_id), 10) + "_key.pem"

	//	Creates and opens a file for writing the private key.
	private_key_file, err_ext := os.OpenFile(private_key_full_path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{7, "Failed to open " + private_key_full_path + " for writing: " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{7, "Failed to open " + private_key_full_path + " for writing: " + err_ext.Error(), ""}
		}
	}

	//	Marshals the private key.
	private_key_bytes, err_ext := x509.MarshalPKCS8PrivateKey(private_key)
	if err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{8, "Unable to marshal private key: " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{8, "Unable to marshal private key: " + err_ext.Error(), ""}
		}
	}

	//	Writes the private key to the file.
	if err_ext := pem.Encode(private_key_file, &pem.Block{Type: "PRIVATE KEY", Bytes: private_key_bytes}); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{9, "Failed to write data to " + private_key_full_path + ": " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{9, "Failed to write data to " + private_key_full_path + ": " + err_ext.Error(), ""}
		}
	}

	//	Closes the file with the private key.
	if err_ext := private_key_file.Close(); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return &logger.ClpError{10, "Error closing " + private_key_full_path + ": " + err_ext.Error(), location}
		} else {
			return &logger.ClpError{10, "Error closing " + private_key_full_path + ": " + err_ext.Error(), ""}
		}
	}
	logger.Debug("%s is written", private_key_full_path)

	return nil
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

	if err_ext := generate_server_certificates(cnf.Bind_address(), cnf.Tls_cert_path(), next_server_id); err_ext != nil {
		if location, err := logger.Get_function_name(); err != nil {
			return nil, &logger.ClpError{2, "Certificate generating failed: " + err_ext.Error(), location}
		} else {
			return nil, &logger.ClpError{2, "Certificate generating failed: " + err_ext.Error(), ""}
		}
	}

	/*
		//	Creates and configures new server.
		server := &http.Server{
			Addr:              cnf.bind_address.String() + ":" + string(cnf.bind_port),
			Handler:           new(incomingConnectionHandler),
			ReadTimeout:       10 * time.Second,
			ReadHeaderTimeout: 0,
			WriteTimeout:      cnf.timeout,
			MaxHeaderBytes:    1 << 12, //	1KB
			ConnState:         process_connection_state,
		}

		//	Starts the server to listen.
		logger.Debug(server.ListenAndServeTLS().Error())
	*/
	//	Puts handle of new server to the handles storage.
	handles[next_server_id] = &Handle{next_server_id, *cnf}
	logger.Info("Server %d has been started", handles[next_server_id].server_id)
	logger.Debug("Server %d configuration: {%+v}", handles[next_server_id].server_id, handles[next_server_id].cnf)

	//	Returns handle of the created server to user.
	return handles[next_server_id], nil
}

func (this *Handle) Stop() {
	//	TO-DO: remove the server data from handles.
	logger.Info("Server %d is stopped", this.server_id)
}
