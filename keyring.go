package https_server

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	"codelearning.online/logger"
)

/*
	Generates a key pair of self-signed X.509 ED25519 certificates for a TLS server (with the specified IP address) and
	writes them to the specified folder using server ID as a part of certificate's filename.

	If the path to folder is empty, then returns certificates as []bytes: both PEM ecncoded certificate and private key.

	Based on https://go.dev/src/crypto/tls/generate_cert.go
*/
func generate_server_ed25519_certificates(bind_address net.IP, path_to_certificates_folder string, server_id uint8) ([]byte, []byte, error) {
	return generate_server_certificates("ed25519", bind_address, path_to_certificates_folder, server_id)
}

/*
	Generates a key pair of self-signed X.509 RSA 2048-bits certificates for a TLS server (with the specified IP address) and
	writes them to the specified folder using server ID as a part of certificate's filename.

	If the path to folder is empty, then returns certificates as []bytes: both PEM ecncoded certificate and private key.

	Based on https://go.dev/src/crypto/tls/generate_cert.go
*/
func generate_server_rsa_certificates(bind_address net.IP, path_to_certificates_folder string, server_id uint8) ([]byte, []byte, error) {
	return generate_server_certificates("rsa", bind_address, path_to_certificates_folder, server_id)
}

//	Returns public key for a given private key.
//	Or, returns nil, is type of the given key is uknown.
func get_public_key(private_key interface{}) interface{} {
	switch key := private_key.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case ed25519.PrivateKey:
		return key.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

//	The main key generator.
func generate_server_certificates(method string, bind_address net.IP, path_to_certificates_folder string, server_id uint8) ([]byte, []byte, error) {

	var private_key interface{}
	var err_ext error
	var key_usage x509.KeyUsage

	switch method {
	case "ed25519":
		//	Generates a ED25519 key that will be used as a private key.
		_, private_key, err_ext = ed25519.GenerateKey(rand.Reader)
		if err_ext != nil {
			location, _ := logger.Get_function_name()
			return nil, nil, &logger.ClpError{
				Code:     1,
				Msg:      "Can't generate a private key: " + err_ext.Error(),
				Location: location}
		}

		//	Prepares digital signature bits.
		key_usage = x509.KeyUsageDigitalSignature
	case "rsa":
		//	Generates an RSA key that will be used as a private key.
		private_key, err_ext = rsa.GenerateKey(rand.Reader, 2048)
		if err_ext != nil {
			location, _ := logger.Get_function_name()
			return nil, nil, &logger.ClpError{
				Code:     1,
				Msg:      "Can't generate a private key: " + err_ext.Error(),
				Location: location}
		}

		//	Prepaes digital signature bits.
		key_usage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	default:
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     1,
			Msg:      "Unknown key type to generate",
			Location: location}
	}

	//	Prepares validity dates. The certificate is valid for one year.
	valid_from := time.Now()
	valid_to := valid_from.Add(365 * 24 * time.Hour)

	//	Generates a serial number.
	serial_number_limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial_number, err_ext := rand.Int(rand.Reader, serial_number_limit)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     2,
			Msg:      "Failed to generate serial number: " + err_ext.Error(),
			Location: location}
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
	certificate, err_ext := x509.CreateCertificate(rand.Reader, &template, &template, get_public_key(private_key), private_key)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     3,
			Msg:      "Failed to create certificate: " + err_ext.Error(),
			Location: location}
	}

	//	Returns certificates if the path to folder is empty.
	if path_to_certificates_folder == "" {

		//	Marshals the private key.
		private_key_bytes, err_ext := x509.MarshalPKCS8PrivateKey(private_key)
		if err_ext != nil {
			location, _ := logger.Get_function_name()
			return nil, nil, &logger.ClpError{
				Code:     4,
				Msg:      "Unable to marshal private key: " + err_ext.Error(),
				Location: location}
		}

		//	Encodes the private key into PEM format.
		private_key_pem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private_key_bytes})
		if private_key_pem == nil {
			location, _ := logger.Get_function_name()
			return nil, nil, &logger.ClpError{
				Code:     5,
				Msg:      "Failed to encode certificate to PEM",
				Location: location}
		}

		//	Encodes the cerificate into PEM format.
		certificate_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
		if certificate_pem == nil {
			location, _ := logger.Get_function_name()
			return nil, nil, &logger.ClpError{
				Code:     6,
				Msg:      "Failed to encode certificate to PEM",
				Location: location}
		}

		logger.Debug("Certificates (S/N %v) are generated", serial_number)
		return certificate_pem, private_key_pem, nil
	}

	certificate_full_path := path_to_certificates_folder + "/" + strconv.FormatUint(uint64(server_id), 10) + "_" + method + ".pem"

	//	Creates a file in filesystem.
	file, err_ext := os.Create(certificate_full_path)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     7,
			Msg:      "Failed to create " + certificate_full_path + ": " + err_ext.Error(),
			Location: location}
	}

	//	Writes the certificate to the file.
	if err_ext := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certificate}); err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     8,
			Msg:      "Failed to open " + certificate_full_path + " for writing: " + err_ext.Error(),
			Location: location}
	}

	//	Closes the file.
	if err_ext := file.Close(); err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     9,
			Msg:      "Error closing " + certificate_full_path + ": " + err_ext.Error(),
			Location: location}
	}
	logger.Debug("%s is written", certificate_full_path)

	private_key_full_path := path_to_certificates_folder + "/" + strconv.FormatUint(uint64(server_id), 10) + "_" + method + "_key.pem"

	//	Creates and opens a file for writing the private key.
	private_key_file, err_ext := os.OpenFile(private_key_full_path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     10,
			Msg:      "Failed to open " + private_key_full_path + " for writing: " + err_ext.Error(),
			Location: location}
	}

	//	Marshals the private key.
	private_key_bytes, err_ext := x509.MarshalPKCS8PrivateKey(private_key)
	if err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     11,
			Msg:      "Unable to marshal private key: " + err_ext.Error(),
			Location: location}
	}

	//	Writes the private key to the file.
	if err_ext := pem.Encode(private_key_file, &pem.Block{Type: "PRIVATE KEY", Bytes: private_key_bytes}); err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     12,
			Msg:      "Failed to write data to " + private_key_full_path + ": " + err_ext.Error(),
			Location: location}
	}

	//	Closes the file with the private key.
	if err_ext := private_key_file.Close(); err_ext != nil {
		location, _ := logger.Get_function_name()
		return nil, nil, &logger.ClpError{
			Code:     13,
			Msg:      "Error closing " + private_key_full_path + ": " + err_ext.Error(),
			Location: location}
	}
	logger.Debug("%s is written", private_key_full_path)

	return nil, nil, nil
}
