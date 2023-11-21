#include "error_print.hpp"

void print_sgx_status(sgx_status_t status)
{
	std::cerr << "=============================================================================" << std::endl;
	std::cerr << "Error name: ";
	
	switch(status)
	{
		case 0x0000:
			std::cerr << "SGX_SUCCESS" << std::endl;
			std::cerr << "Exited SGX function successfully." << std::endl;
			break;
		
		case 0x0001:
			std::cerr << "SGX_ERROR_UNEXPECTED" << std::endl;
			std::cerr << "An unexpected error has occured." << std::endl;
			break;

		case 0x0002:
			std::cerr << "SGX_ERROR_INVALID_PARAMETER" << std::endl;
			std::cerr << "The parameter is incorrect. Please check the argument of function." << std::endl;
			break;

		case 0x0003:
			std::cerr << "SGX_ERROR_OUT_OF_MEMORY" << std::endl;
			std::cerr << "There is not enough memory available to complete this operation." << std::endl;
			break;

		case 0x0004:
			std::cerr << "SGX_ERROR_ENCLAVE_LOST" << std::endl;
			std::cerr << "The enclave is lost after power transition." << std::endl;
			break;

		case 0x0005:
			std::cerr << "SGX_ERROR_INVALID_STATE" << std::endl;
			std::cerr << "The API is invoked in incorrect order or state." << std::endl;
			break;

		case 0x0007:
			std::cerr << "SGX_ERROR_HYPERV_ENABLED" << std::endl;
			std::cerr << "Incompatible versions of Windows* 10 OS and Hyper-V* are detected." << std::endl;
			std::cerr << "In this case, you need to disable Hyper-V on the target machine." << std::endl;
			break;

		case 0x0008:
			std::cerr << "SGX_ERROR_FEATURE_NOT_SUPPORTED" << std::endl;
			std::cerr << "The feature has been deprecated and is no longer supported." << std::endl;
			break;

		case 0x1001:
			std::cerr << "SGX_ERROR_INVALID_FUNCTION" << std::endl;
			std::cerr << "The ECALL/OCALL function index is incorrect." << std::endl;
			break;

		case 0x1003:
			std::cerr << "SGX_ERROR_OUT_OF_TCS" << std::endl;
			std::cerr << "The enclave is out of Thread Control Structure." << std::endl;
			break;

		case 0x1006:
			std::cerr << "SGX_ERROR_ENCLAVE_CRASHED" << std::endl;
			std::cerr << "The enclave has crashed." << std::endl;
			break;

		case 0x1007:
			std::cerr << "SGX_ERROR_ECALL_NOT_ALLOWED" << std::endl;
			std::cerr << "ECALL is not allowed at this time. For example:" << std::endl;
			std::cerr << "- ECALL is not public." << std::endl;
			std::cerr << "- ECALL is blocked by the dynamic entry table." << std::endl;
			std::cerr << "- A nested ECALL is not allowed during global initialization." << std::endl;
			break;

		case 0x1008:
			std::cerr << "SGX_ERROR_OCALL_NOT_ALLOWED" << std::endl;
			std::cerr << "OCALL is not allowed during exception handling." << std::endl;
			break;

		case 0x2000:
			std::cerr << "SGX_ERROR_UNDEFINED_SYMBOL" << std::endl;
			std::cerr << "The enclave image has undefined symbol." << std::endl;
			break;

		case 0x2001:
			std::cerr << "SGX_ERROR_INVALID_ENCLAVE" << std::endl;
			std::cerr << "The enclave image is incorrect." << std::endl;
			break;

		case 0x2002:
			std::cerr << "SGX_ERROR_INVALID_ENCLAVE_ID" << std::endl;
			std::cerr << "The enclave ID is invalid." << std::endl;
			break;

		case 0x2003:
			std::cerr << "SGX_ERROR_INVALID_SIGNATURE" << std::endl;
			std::cerr << "The signature is invalid." << std::endl;
			break;

		case 0x2004:
			std::cerr << "SGX_ERROR_NDEBUG_ENCLAVE" << std::endl;
			std::cerr << "The enclave is signed as product enclave and cannot be created" << std::endl
					<< "as a debuggable enclave." << std::endl;
			break;

		case 0x2005:
			std::cerr << "SGX_ERROR_OUT_OF_EPC" << std::endl;
			std::cerr << "There is not enough EPC available to load the enclave" << std::endl
					<< "or one of the Architecture Enclave needed to complete" << std::endl
					<< "the operation requested." << std::endl;
			break;

		case 0x2006:
			std::cerr << "SGX_ERROR_NO_DEVICE" << std::endl;
			std::cerr << "Cannot open device." << std::endl;
			break;

		case 0x2007:
			std::cerr << "SGX_ERROR_MEMORY_MAP_CONFLICT" << std::endl;
			std::cerr << "Page mapping failed in driver." << std::endl;
			break;

		case 0x2009:
			std::cerr << "SGX_ERROR_INVALID_METADATA" << std::endl;
			std::cerr << "The metadata is incorrect." << std::endl;
			break;

		case 0x200C:
			std::cerr << "SGX_ERROR_DEVICE_BUSY" << std::endl;
			std::cerr << "Device is busy." << std::endl;
			break;

		case 0x200D:
			std::cerr << "SGX_ERROR_INVALID_VERSION" << std::endl;
			std::cerr << "Metadata version is inconsistent between uRTS and sgx_sign" << std::endl
					<< "or the uRTS is incompatible with the current platform." << std::endl;
			break;

		case 0x200E:
			std::cerr << "SGX_ERROR_MODE_INCOMPATIBLE" << std::endl;
			std::cerr << "The target enclave (32/64 bit or HS/Sim) mode is incompatible" << std::endl
					<< "with the uRTS mode." << std::endl;
			break;

		case 0x200F:
			std::cerr << "SGX_ERROR_ENCLAVE_FILE_ACCESS" << std::endl;
			std::cerr << "Cannot open enclave file." << std::endl;
			break;

		case 0x2010:
			std::cerr << "SGX_ERROR_INVALID_MISC" << std::endl;
			std::cerr << "The MiscSelect/MiscMask settings are incorrect." << std::endl;
			break;

		case 0x2012:
			std::cerr << "SGX_ERROR_MEMORY_LOCKED" << std::endl;
			std::cerr << "Attempt to change system memory that should not be modified." << std::endl;
			break;

		case 0x3001:
			std::cerr << "SGX_ERROR_MAC_MISMATCH" << std::endl;
			std::cerr << "Indicates report verification or cryptographic error." << std::endl;
			break;

		case 0x3002:
			std::cerr << "SGX_ERROR_INVALID_ATTRIBUTE" << std::endl;
			std::cerr << "The enclave is not authorized." << std::endl;
			break;

		case 0x3003:
			std::cerr << "SGX_ERROR_INVALID_CPUSVN" << std::endl;
			std::cerr << "The CPU SVN is beyond the CPU SVN value of the platform." << std::endl;
			break;

		case 0x3004:
			std::cerr << "SGX_ERROR_INVALID_ISVSVN" << std::endl;
			std::cerr << "The ISV SVN is greater than the ISV SVN value of the enclave." << std::endl;
			break;

		case 0x3005:
			std::cerr << "SGX_ERROR_INVALID_KEYNAME" << std::endl;
			std::cerr << "Unsupported key name value." << std::endl;
			break;

		case 0x4001:
			std::cerr << "SGX_ERROR_SERVICE_UNAVAILABLE" << std::endl;
			std::cerr << "AE service did not respond or the requested service is not supported." << std::endl
					<< "Probably aesmd service is corrupted, so try reinstalling Intel SGX driver." << std::endl;
			break;

		case 0x4002:
			std::cerr << "SGX_ERROR_SERVICE_TIMEOUT" << std::endl;
			std::cerr << "The request to AE service timed out." << std::endl;
			break;

		case 0x4003:
			std::cerr << "SGX_ERROR_AE_INVALID_EPIDBLOB" << std::endl;
			std::cerr << "Indicates an Intel(R) EPID blob verification error." << std::endl;
			break;

		case 0x4004:
			std::cerr << "SGX_ERROR_SERVICE_INVALID_PRIVILEDGE" << std::endl;
			std::cerr << "Enclave has no priviledge to get launch token." << std::endl;
			break;

		case 0x4005:
			std::cerr << "SGX_ERROR_EPID_MEMBER_REVOKED" << std::endl;
			std::cerr << "The Intel(R) EPID group membership has been revoked." << std::endl
					<< "The platform is not trusted. Updating platform and retrying" << std::endl
					<< "will not remedy the revocation." << std::endl;
			break;

		case 0x4006:
			std::cerr << "SGX_ERROR_UPDATE_NEEDED" << std::endl;
			std::cerr << "Intel(R) SGX needs to be updated." << std::endl;
			break;

		case 0x4007:
			std::cerr << "SGX_ERROR_NETWORK_FAILURE" << std::endl;
			std::cerr << "Network connecting or proxy setting issue is encountered." << std::endl;
			break;

		case 0x4008:
			std::cerr << "SGX_ERROR_AE_SESSION_INVALID" << std::endl;
			std::cerr << "The session is invalid or ended by AE service." << std::endl;
			break;

		case 0x400a:
			std::cerr << "SGX_ERROR_BUSY" << std::endl;
			std::cerr << "The requested service is temporarily not available." << std::endl;
			break;

		case 0x400c:
			std::cerr << "SGX_ERROR_MC_NOT_FOUND" << std::endl;
			std::cerr << "The Monotonic Counter does not exist or has been invalidated." << std::endl;
			break;

		case 0x400d:
			std::cerr << "SGX_ERROR_MC_NO_ACCESS_RIGHT" << std::endl;
			std::cerr << "The caller does not have the access right to the specified VMC." << std::endl;
			break;

		case 0x400e:
			std::cerr << "SGX_ERROR_MC_USED_UP" << std::endl;
			std::cerr << "No Monotonic Counter is available." << std::endl;
			break;

		case 0x400f:
			std::cerr << "SGX_ERROR_MC_OVER_QUOTA" << std::endl;
			std::cerr << "Monotonic Counter reached quota limit." << std::endl;
			break;

		case 0x4011:
			std::cerr << "SGX_ERROR_KDF_MISMATCH" << std::endl;
			std::cerr << "Key derivation function does not match during key exchange." << std::endl;
			break;

		case 0x4012:
			std::cerr << "SGX_ERROR_UNRECOGNIZED_PLATFORM" << std::endl;
			std::cerr << "Intel(R) EPID Provisioning failed because the platform was not recognized" << std::endl
					<< "by the back-end server." << std::endl;
			break;

		case 0x4013:
			std::cerr << "SGX_ERROR_SM_SERVICE_CLOSED" << std::endl;
			std::cerr << "The secure message service instance was closed." << std::endl;
			break;

		case 0x4014:
			std::cerr << "SGX_ERROR_SM_SERVICE_UNAVAILABLE" << std::endl;
			std::cerr << "The secure message service applet does not have an existing session." << std::endl;
			break;

		case 0x4015:
			std::cerr << "SGX_ERROR_SM_SERVICE_UNCAUGHT_EXCEPTION" << std::endl;
			std::cerr << "The secure message service instance was terminated with an uncaught exception." << std::endl;
			break;

		case 0x4016:
			std::cerr << "SGX_ERROR_SM_SERVICE_RESPONSE_OVERFLOW" << std::endl;
			std::cerr << "The response data of the service applet is too large." << std::endl;
			break;

		case 0x4017:
			std::cerr << "SGX_ERROR_SM_SERVICE_INTERNAL_ERROR" << std::endl;
			std::cerr << "The secure message service got an internal error." << std::endl;
			break;

		case 0x5002:
			std::cerr << "SGX_ERROR_NO_PRIVILEDGE" << std::endl;
			std::cerr << "You do not have enough priviledges to perform the operation." << std::endl;
			break;

		case 0x6001:
			std::cerr << "SGX_ERROR_PCL_ENCRYPTED" << std::endl;
			std::cerr << "Trying to encrypt an already encrypted enclave." << std::endl;
			break;

		case 0x6002:
			std::cerr << "SGX_ERROR_PCL_NOT_ENCRYPTED" << std::endl;
			std::cerr << "Trying to load a plain enclave using sgx_created_encrypted_enclave." << std::endl;
			break;

		case 0x6003:
			std::cerr << "SGX_ERROR_PCL_MAC_MISMATCH" << std::endl;
			std::cerr << "Section MAC result does not match build time MAC." << std::endl;
			break;

		case 0x6004:
			std::cerr << "SGX_ERROR_PCL_SHA_MISMATCH" << std::endl;
			std::cerr << "Unsealed key MAC doesn't match MAC of key hardcoded in enclave binary." << std::endl;
			break;

		case 0x6005:
			std::cerr << "SGX_ERROR_PCL_GUID_MISMATCH" << std::endl;
			std::cerr << "GUID in sealed blob doesn't match GUID hardcoded in enclave binary." << std::endl;
			break;

		case 0x7001:
			std::cerr << "SGX_ERROR_FILE_BAD_STATUS" << std::endl;
			std::cerr << "The file is in a bad status, run sgx_clearerr to try and fix it." << std::endl;
			break;

		case 0x7002:
			std::cerr << "SGX_ERROR_FILE_NO_KEY_ID" << std::endl;
			std::cerr << "The Key ID field is all zeros, cannot re-generate the encryption key." << std::endl;
			break;

		case 0x7003:
			std::cerr << "SGX_ERROR_FILE_NAME_MISMATCH" << std::endl;
			std::cerr << "The current file name is different than the original file name" << std::endl
					<< "(not allowed, substitution attack)." << std::endl;
			break;

		case 0x7004:
			std::cerr << "SGX_ERROR_FILE_NOT_SGX_FILE" << std::endl;
			std::cerr << "The file is not an Intel SGX file." << std::endl;
			break;

		case 0x7005:
			std::cerr << "SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE" << std::endl;
			std::cerr << "A recovery file cannot be opened, so the flush operation cannot continue" << std::endl
					<< "(only used when no EXXX is returned)." << std::endl;
			break;

		case 0x7006:
			std::cerr << "SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE" << std::endl;
			std::cerr << "A recovery file cannot be writen, so the flush operation cannot continue" << std::endl
					<< "(only used when no EXXX is returned)." << std::endl;
			break;

		case 0x7007:
			std::cerr << "SGX_ERROR_FILE_RECOVERY_NEEDED" << std::endl;
			std::cerr << "When opening the file, recovery is needed, but the recovery process failed." << std::endl;
			break;

		case 0x7008:
			std::cerr << "SGX_ERROR_FILE_FLUSH_FAILED" << std::endl;
			std::cerr << "fflush operation (to the disk) failed (only used when no EXXX is returned)." << std::endl;
			break;

		case 0x7009:
			std::cerr << "SGX_ERROR_FILE_CLOSE_FAILED" << std::endl;
			std::cerr << "fclose operation (to the disk) failed (only used when no EXXX is returned)." << std::endl;
			break;

		case 0x8001:
			std::cerr << "SGX_ERROR_IPLDR_NOTENCRYPTED" << std::endl;
			std::cerr << "sgx_create_encrypted_enclave was called, but the enclave file is not encrypted." << std::endl;
			break;

		case 0x8002:
			std::cerr << "SGX_ERROR_IPLDR_MAC_MISMATCH" << std::endl;
			std::cerr << "sgx_create_encrypted_enclave was called but there was a verification error" << std::endl
					<< "when decrypting the data." << std::endl;
			break;

		case 0x8003:
			std::cerr << "SGX_ERROR_IPLDR_ENCRYPTED" << std::endl;
			std::cerr << "sgx_create_encrypted_enclave was called, but the enclave file is encrypted." << std::endl;
			break;

		case 0xf001:
			std::cerr << "SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED" << std::endl;
			std::cerr << "The ioctl for enclave_create unexpectedly failed with EINTR." << std::endl;
			break;
	
		default:
			std::cerr << "Unrecognized SGX status code." << std::endl;
	}

	std::cerr << "=============================================================================" << std::endl;

	return;
}


/* DCAP-RA用エラー表示 */
void print_ql_status(quote3_error_t qe3_error)
{
	std::cerr << "=============================================================================" << std::endl;
	std::cerr << "Error name: ";
	
	switch(qe3_error)
	{
		case SGX_QL_SUCCESS:
			std::cerr << "SGX_QL_SUCCESS" << std::endl;
			std::cerr << "Exited SGX QL function successfully." << std::endl;
			break;
		
		case SGX_QL_ERROR_UNEXPECTED:
			std::cerr << "SGX_QL_ERROR_UNEXPECTED" << std::endl;
			std::cerr << "An unexpected error has occured." << std::endl;
			break;
		
		case SGX_QL_ERROR_INVALID_PARAMETER:
			std::cerr << "SGX_QL_ERROR_INVALID_PARAMETER" << std::endl;
			std::cerr << "The parameter is incorrect." << std::endl;
			break;
		
		case SGX_QL_ERROR_OUT_OF_MEMORY:
			std::cerr << "SGX_QL_ERROR_OUT_OF_MEMORY" << std::endl;
			std::cerr << "Not enough memory is available to complete this operation." << std::endl;
			break;

		case SGX_QL_ERROR_ECDSA_ID_MISMATCH:
			std::cerr << "SGX_QL_ERROR_ECDSA_ID_MISMATCH" << std::endl;
			std::cerr << "Expected ECDSA_ID does not match the value stored in the ECDSA Blob." << std::endl;
			break;

		case SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR:
			std::cerr << "SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR" << std::endl;
			std::cerr << "The ECDSA blob pathname is too large." << std::endl;
			break;

		case SGX_QL_FILE_ACCESS_ERROR:
			std::cerr << "SGX_QL_FILE_ACCESS_ERROR" << std::endl;
			std::cerr << "Error accessing ECDSA blob." << std::endl;
			break;

		case SGX_QL_ERROR_STORED_KEY:
			std::cerr << "SGX_QL_ERROR_STORED_KEY" << std::endl;
			std::cerr << "Cached ECDSA key is invalid." << std::endl;
			break;
		
		case SGX_QL_ERROR_PUB_KEY_ID_MISMATCH:
			std::cerr << "SGX_QL_ERROR_PUB_KEY_ID_MISMATCH" << std::endl;
			std::cerr << "Cached ECDSA key does not match requested key." << std::endl;
			break;
		
		case SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME:
			std::cerr << "SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME" << std::endl;
			std::cerr << "PCE use the incorrect signature scheme." << std::endl;
			break;
		
		case SGX_QL_ATT_KEY_BLOB_ERROR:
			std::cerr << "SGX_QL_ATT_KEY_BLOB_ERROR" << std::endl;
			std::cerr << "There is a problem with the attestation key blob." << std::endl;
			break;
		
		case SGX_QL_UNSUPPORTED_ATT_KEY_ID:
			std::cerr << "SGX_QL_UNSUPPORTED_ATT_KEY_ID" << std::endl;
			std::cerr << "Unsupported attestation key ID." << std::endl;
			break;

		case SGX_QL_UNSUPPORTED_LOADING_POLICY:
			std::cerr << "SGX_QL_UNSUPPORTED_LOADING_POLICY" << std::endl;
			std::cerr << "Unsupported enclave loading policy." << std::endl;
			break;

		case SGX_QL_INTERFACE_UNAVAILABLE:
			std::cerr << "SGX_QL_INTERFACE_UNAVAILABLE" << std::endl;
			std::cerr << "Unable to load the PCE enclave." << std::endl;
			break;

		case SGX_QL_PLATFORM_LIB_UNAVAILABLE:
			std::cerr << "SGX_QL_PLATFORM_LIB_UNAVAILABLE" << std::endl;
			std::cerr << "Unable to find the platform library with the dependent APIs. Not fatal." << std::endl;
			break;

		case SGX_QL_ATT_KEY_NOT_INITIALIZED:
			std::cerr << "SGX_QL_ATT_KEY_NOT_INITIALIZED" << std::endl;
			std::cerr << "The attestation key doesn't exist or has not been certified." << std::endl;
			break;
		
		case SGX_QL_ATT_KEY_CERT_DATA_INVALID:
			std::cerr << "SGX_QL_ATT_KEY_CERT_DATA_INVALID" << std::endl;
			std::cerr << "The certification data retrieved from the platform library is invalid." << std::endl;
			break;

		case SGX_QL_NO_PLATFORM_CERT_DATA:
			std::cerr << "SGX_QL_NO_PLATFORM_CERT_DATA" << std::endl;
			std::cerr << "The platform library doesn't have any platfrom cert data." << std::endl;
			break;
	
		case SGX_QL_OUT_OF_EPC:
			std::cerr << "SGX_QL_OUT_OF_EPC" << std::endl;
			std::cerr << "Not enough memory in the EPC to load the enclave." << std::endl;
			break;
	
		case SGX_QL_ERROR_REPORT:
			std::cerr << "SGX_QL_ERROR_REPORT" << std::endl;
			std::cerr << "There was a problem verifying an SGX REPORT." << std::endl;
			break;
	
		case SGX_QL_ENCLAVE_LOST:
			std::cerr << "SGX_QL_ENCLAVE_LOST" << std::endl;
			std::cerr << "Interfacing to the enclave failed due to a power transition." << std::endl;
			break;
	
		case SGX_QL_INVALID_REPORT:
			std::cerr << "SGX_QL_INVALID_REPORT" << std::endl;
			std::cerr << "Error verifying the application enclave's report." << std::endl;
			break;
	
		case SGX_QL_ENCLAVE_LOAD_ERROR:
			std::cerr << "SGX_QL_ENCLAVE_LOAD_ERROR" << std::endl;
			std::cerr << "Unable to load the enclaves. Could be due to file I/O error, ";
			std::cerr << "loading infrastructure error, or non-SGX capable system." << std::endl;
			break;
	
		case SGX_QL_UNABLE_TO_GENERATE_QE_REPORT:
			std::cerr << "SGX_QL_UNABLE_TO_GENERATE_QE_REPORT" << std::endl;
			std::cerr << "The QE was unable to generate its own report targeting the application enclave either";
			std::cerr << "because the QE doesn't support this feature there is an enclave compatibility issue.";
			std::cerr << "Please call again with the p_qe_report_info to NULL." << std::endl;
			break;

		case SGX_QL_KEY_CERTIFCATION_ERROR:
			std::cerr << "SGX_QL_KEY_CERTIFCATION_ERROR" << std::endl;
			std::cerr << "Caused when the provider library returns an invalid TCB (too high)." << std::endl;
			break;

		case SGX_QL_NETWORK_ERROR:
			std::cerr << "SGX_QL_NETWORK_ERROR" << std::endl;
			std::cerr << "Network error when retrieving PCK certs." << std::endl;
			break;

		case SGX_QL_MESSAGE_ERROR:
			std::cerr << "SGX_QL_MESSAGE_ERROR" << std::endl;
			std::cerr << "Message error when retrieving PCK certs." << std::endl;
			break;

		case SGX_QL_NO_QUOTE_COLLATERAL_DATA:
			std::cerr << "SGX_QL_NO_QUOTE_COLLATERAL_DATA" << std::endl;
			std::cerr << "The platform does not have the quote verification collateral data available." << std::endl;
			break;

		case SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED:
			std::cerr << "SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED" << std::endl;
			std::cerr << "The quote verifier doesn’t support the certification data in the Quote." << std::endl;
			break;

		case SGX_QL_QUOTE_FORMAT_UNSUPPORTED:
			std::cerr << "SGX_QL_QUOTE_FORMAT_UNSUPPORTED" << std::endl;
			std::cerr << "The inputted quote format is not supported. Either because the header information is not supported "; 
			std::cerr << "or the quote is malformed in some way." << std::endl;
			break;

		case SGX_QL_UNABLE_TO_GENERATE_REPORT:
			std::cerr << "SGX_QL_UNABLE_TO_GENERATE_REPORT" << std::endl;
			std::cerr << "The QVE was unable to generate its own report targeting the application enclave ";
			std::cerr << "because there is an enclave compatibility issue." << std::endl;
			break;

		case SGX_QL_QE_REPORT_INVALID_SIGNATURE:
			std::cerr << "SGX_QL_QE_REPORT_INVALID_SIGNATURE" << std::endl;
			std::cerr << "The signature over the QE Report is invalid." << std::endl;
			break;

		case SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT:
			std::cerr << "SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT" << std::endl;
			std::cerr << "The quote verifier doesn’t support the format of the application REPORT the Quote." << std::endl;
			break;

		case SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT:
			std::cerr << "SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT" << std::endl;
			std::cerr << "The format of the PCK Cert is unsupported." << std::endl;
			break;

		case SGX_QL_PCK_CERT_CHAIN_ERROR:
			std::cerr << "SGX_QL_PCK_CERT_CHAIN_ERROR" << std::endl;
			std::cerr << "Cannot parse the PCK certificate chain, or root certificate is not trusted." << std::endl;
			break;

		case SGX_QL_TCBINFO_UNSUPPORTED_FORMAT:
			std::cerr << "SGX_QL_TCBINFO_UNSUPPORTED_FORMAT" << std::endl;
			std::cerr << "The format of the TCBInfo structure is unsupported." << std::endl;
			break;

		case SGX_QL_TCBINFO_MISMATCH:
			std::cerr << "SGX_QL_TCBINFO_MISMATCH" << std::endl;
			std::cerr << "PCK Cert FMSPc does not match the TCBInfo FMSPc." << std::endl;
			break;

		case SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT:
			std::cerr << "SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT" << std::endl;
			std::cerr << "The format of the QEIdentity structure is unsupported." << std::endl;
			break;

		case SGX_QL_QEIDENTITY_MISMATCH:
			std::cerr << "SGX_QL_QEIDENTITY_MISMATCH" << std::endl;
			std::cerr << "The Quote’s QE doesn’t match the inputted expected QEIdentity." << std::endl;
			break;

		case SGX_QL_TCB_OUT_OF_DATE:
			std::cerr << "SGX_QL_TCB_OUT_OF_DATE" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
			std::cerr << "SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
			std::cerr << "SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
			std::cerr << "SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_QE_IDENTITY_OUT_OF_DATE:
			std::cerr << "SGX_QL_QE_IDENTITY_OUT_OF_DATE" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_SGX_TCB_INFO_EXPIRED:
			std::cerr << "SGX_QL_SGX_TCB_INFO_EXPIRED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED:
			std::cerr << "SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_SGX_CRL_EXPIRED:
			std::cerr << "SGX_QL_SGX_CRL_EXPIRED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED:
			std::cerr << "SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED:
			std::cerr << "SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_PCK_REVOKED:
			std::cerr << "SGX_QL_PCK_REVOKED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_TCB_REVOKED:
			std::cerr << "SGX_QL_TCB_REVOKED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_TCB_CONFIGURATION_NEEDED:
			std::cerr << "SGX_QL_TCB_CONFIGURATION_NEEDED" << std::endl;
			std::cerr << "(Detail is not provided by Intel. Probably related to RA result status)" << std::endl;
			break;

		case SGX_QL_UNABLE_TO_GET_COLLATERAL:
			std::cerr << "SGX_QL_UNABLE_TO_GET_COLLATERAL" << std::endl;
			std::cerr << "Failed to retrieve collateral." << std::endl;
			break;

		case SGX_QL_ERROR_INVALID_PRIVILEGE:
			std::cerr << "SGX_QL_ERROR_INVALID_PRIVILEGE" << std::endl;
			std::cerr << "No enough privilege to perform the operation." << std::endl;
			break;

		case SGX_QL_NO_QVE_IDENTITY_DATA:
			std::cerr << "SGX_QL_NO_QVE_IDENTITY_DATA" << std::endl;
			std::cerr << "The platform does not have the QVE identity data available." << std::endl;
			break;

		case SGX_QL_CRL_UNSUPPORTED_FORMAT:
			std::cerr << "SGX_QL_CRL_UNSUPPORTED_FORMAT" << std::endl;
			std::cerr << "(Detail is not provided by Intel.)" << std::endl;
			break;
		
		case SGX_QL_QEIDENTITY_CHAIN_ERROR:
			std::cerr << "SGX_QL_QEIDENTITY_CHAIN_ERROR" << std::endl;
			std::cerr << "There was an error verifying the QEIdentity signature chain including QEIdentity revocation." << std::endl;
			break;

		case SGX_QL_TCBINFO_CHAIN_ERROR:
			std::cerr << "SGX_QL_TCBINFO_CHAIN_ERROR" << std::endl;
			std::cerr << "There was an error verifying the TCBInfo signature chain including TCBInfo revocation." << std::endl;
			break;

		case SGX_QL_ERROR_QVL_QVE_MISMATCH:
			std::cerr << "SGX_QL_ERROR_QVL_QVE_MISMATCH" << std::endl;
			std::cerr << "Supplemental data size and version mismatched between QVL and QvE. ";
			std::cerr << "Please make sure to use QVL and QvE from same release package. " << std::endl;
			break;

		case SGX_QL_TCB_SW_HARDENING_NEEDED:
			std::cerr << "SGX_QL_TCB_SW_HARDENING_NEEDED" << std::endl;
			std::cerr << "TCB up to date but SW Hardening needed." << std::endl;
			break;

		case SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
			std::cerr << "SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED" << std::endl;
			std::cerr << "TCB up to date but Configuration and SW Hardening needed." << std::endl;
			break;

		case SGX_QL_UNSUPPORTED_MODE:
			std::cerr << "SGX_QL_UNSUPPORTED_MODE" << std::endl;
			std::cerr << "The platform has been configured to use the out-of-process implementation of quote generation." << std::endl;
			break;

		case SGX_QL_NO_DEVICE:
			std::cerr << "SGX_QL_NO_DEVICE" << std::endl;
			std::cerr << "Can't open SGX device. This error happens only when running in out-of-process mode." << std::endl;
			break;

		case SGX_QL_SERVICE_UNAVAILABLE:
			std::cerr << "SGX_QL_SERVICE_UNAVAILABLE" << std::endl;
			std::cerr << "Indicates AESM didn't respond or the requested service is not supported. ";
			std::cerr << "This error happens only when running in out-of-process mode." << std::endl;
			break;

		case SGX_QL_NETWORK_FAILURE:
			std::cerr << "SGX_QL_NETWORK_FAILURE" << std::endl;
			std::cerr << "Network connection or proxy setting issue is encountered. ";
			std::cerr << "This error happens only when running in out-of-process mode." << std::endl;
			break;

		case SGX_QL_SERVICE_TIMEOUT:
			std::cerr << "SGX_QL_SERVICE_TIMEOUT" << std::endl;
			std::cerr << "The request to out-of-process service has timed out. ";
			std::cerr << "This error happens only when running in out-of-process mode." << std::endl;
			break;

		case SGX_QL_ERROR_BUSY:
			std::cerr << "SGX_QL_ERROR_BUSY" << std::endl;
			std::cerr << "The requested service is temporarily not available. ";
			std::cerr << "This error happens only when running in outof-process mode." << std::endl;
			break;

		case SGX_QL_UNKNOWN_MESSAGE_RESPONSE:
			std::cerr << "SGX_QL_UNKNOWN_MESSAGE_RESPONSE" << std::endl;
			std::cerr << "Unexpected error from the cache service." << std::endl;
			break;

		case SGX_QL_PERSISTENT_STORAGE_ERROR:
			std::cerr << "SGX_QL_PERSISTENT_STORAGE_ERROR" << std::endl;
			std::cerr << "Error storing the retrieved cached data in persistent memory." << std::endl;
			break;

		case SGX_QL_ERROR_MESSAGE_PARSING_ERROR:
			std::cerr << "SGX_QL_ERROR_MESSAGE_PARSING_ERROR" << std::endl;
			std::cerr << "Message parsing error." << std::endl;
			break;

		case SGX_QL_PLATFORM_UNKNOWN:
			std::cerr << "SGX_QL_PLATFORM_UNKNOWN" << std::endl;
			std::cerr << "Platform was not found in the cache." << std::endl;
			break;

		case SGX_QL_UNKNOWN_API_VERSION:
			std::cerr << "SGX_QL_UNKNOWN_API_VERSION" << std::endl;
			std::cerr << "The current PCS API version configured is unknown." << std::endl;
			break;

		case SGX_QL_CERTS_UNAVAILABLE:
			std::cerr << "SGX_QL_CERTS_UNAVAILABLE" << std::endl;
			std::cerr << "Certificates are not available for this platform." << std::endl;
			break;

		case SGX_QL_QVEIDENTITY_MISMATCH:
			std::cerr << "SGX_QL_QVEIDENTITY_MISMATCH" << std::endl;
			std::cerr << "QvE Identity is NOT match to Intel signed QvE identity." << std::endl;
			break;

		case SGX_QL_QVE_OUT_OF_DATE:
			std::cerr << "SGX_QL_QVE_OUT_OF_DATE" << std::endl;
			std::cerr << "QvE ISVSVN is smaller than the ISVSVN threshold, or input QvE ISVSVN is too small." << std::endl;
			break;

		case SGX_QL_PSW_NOT_AVAILABLE:
			std::cerr << "SGX_QL_PSW_NOT_AVAILABLE" << std::endl;
			std::cerr << "SGX PSW library cannot be loaded, could be due to file I/O error." << std::endl;
			break;

		case SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED:
			std::cerr << "SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED" << std::endl;
			std::cerr << "SGX quote verification collateral version not supported by QVL/QvE." << std::endl;
			break;

		case SGX_QL_TDX_MODULE_MISMATCH:
			std::cerr << "SGX_QL_TDX_MODULE_MISMATCH" << std::endl;
			std::cerr << "TDX SEAM module identity is NOT match to Intel signed TDX SEAM module." << std::endl;
			break;

		case SGX_QL_QEIDENTITY_NOT_FOUND:
			std::cerr << "SGX_QL_QEIDENTITY_NOT_FOUND" << std::endl;
			std::cerr << "QE identity was not found." << std::endl;
			break;

		case SGX_QL_TCBINFO_NOT_FOUND:
			std::cerr << "SGX_QL_TCBINFO_NOT_FOUND" << std::endl;
			std::cerr << "TCB Info was not found." << std::endl;
			break;

		case SGX_QL_INTERNAL_SERVER_ERROR:
			std::cerr << "SGX_QL_INTERNAL_SERVER_ERROR" << std::endl;
			std::cerr << "Internal server error." << std::endl;
			break;

		case SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED:
			std::cerr << "SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED" << std::endl;
			std::cerr << "The supplemental data version is not supported." << std::endl;
			break;

		case SGX_QL_ROOT_CA_UNTRUSTED:
			std::cerr << "SGX_QL_ROOT_CA_UNTRUSTED" << std::endl;
			std::cerr << "The certificate used to establish SSL session is untrusted." << std::endl;
			break;

		case SGX_QL_TCB_NOT_SUPPORTED:
			std::cerr << "SGX_QL_TCB_NOT_SUPPORTED" << std::endl;
			std::cerr << "Current TCB level cannot be found in platform/enclave TCB info." << std::endl;
			break;

		case SGX_QL_CONFIG_INVALID_JSON:
			std::cerr << "SGX_QL_CONFIG_INVALID_JSON" << std::endl;
			std::cerr << "The QPL's config file is in JSON format but has a format error." << std::endl;
			break;

		case SGX_QL_RESULT_INVALID_SIGNATURE:
			std::cerr << "SGX_QL_RESULT_INVALID_SIGNATURE" << std::endl;
			std::cerr << "Invalid signature during quote verification." << std::endl;
			break;

		case SGX_QL_ERROR_MAX:
			std::cerr << "SGX_QL_ERROR_MAX" << std::endl;
			std::cerr << "Indicate max error to allow better translation. For internal error management." << std::endl;
			break;
	
		default:
			std::cerr << "Unrecognized SGX status code." << std::endl;
	}

	std::cerr << "=============================================================================" << std::endl;

	return;
}
