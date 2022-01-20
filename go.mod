module codelearning.online/https_server

go 1.17

replace codelearning.online/logger => ../logger

replace codelearning.online/conf => ../conf

require (
	codelearning.online/conf v0.0.0-00010101000000-000000000000
	codelearning.online/logger v0.0.0-00010101000000-000000000000
)
