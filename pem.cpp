#include "stdafx.h"

NTSTATUS openssl_verify(_In_ BCRYPT_KEY_HANDLE hKey,
						_In_ PCUCHAR pbToBeSigned, 
						_In_ ULONG cbToBeSigned,
						_In_ PCUCHAR pbSignature, 
						_In_ ULONG cbSignature,
						_In_ PCWSTR pszAlgId)
{
	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0);

	if (0 <= status)
	{
		BCRYPT_HASH_HANDLE hHash = 0;

		ULONG HashBlockLength, cb;

		0 <= (status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&HashBlockLength, sizeof(ULONG), &cb, 0)) &&
			0 <= (status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, 0, 0, 0));

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			PUCHAR pbHash = (PUCHAR)alloca(HashBlockLength);

			0 <= (status = BCryptHashData(hHash, const_cast<PUCHAR>(pbToBeSigned), cbToBeSigned, 0)) &&
				0 <= (status = BCryptFinishHash(hHash, pbHash, HashBlockLength, 0));

			BCryptDestroyHash(hHash);

			if (0 <= status)
			{
				BCRYPT_PKCS1_PADDING_INFO pi = { pszAlgId };

				status = BCryptVerifySignature(hKey, &pi, pbHash, HashBlockLength, 
					const_cast<PUCHAR>(pbSignature), cbSignature, BCRYPT_PAD_PKCS1);
			}
		}
	}

	return status;
}

inline NTSTATUS openssl_verify(_In_ BCRYPT_KEY_HANDLE hKey,
							   _In_ PCSTR szToBeSigned,
							   _In_ PCUCHAR pbSignature, 
							   _In_ ULONG cbSignature,
							   _In_ PCWSTR pszAlgId)
{
	return openssl_verify(hKey, (PCUCHAR)szToBeSigned, (ULONG)strlen(szToBeSigned), pbSignature, cbSignature, pszAlgId);
}

NTSTATUS openssl_sign(_In_ BCRYPT_KEY_HANDLE hKey,
					  _In_ PCUCHAR pbToBeSigned, 
					  _In_ ULONG cbToBeSigned,
					  _Out_ PUCHAR pbSignature, 
					  _Inout_ PULONG pcbSignature,
					  _In_ PCWSTR pszAlgId)
{
	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0);

	if (0 <= status)
	{
		BCRYPT_HASH_HANDLE hHash = 0;

		ULONG HashBlockLength, cb;

		0 <= (status = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&HashBlockLength, sizeof(ULONG), &cb, 0)) &&
			0 <= (status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, 0, 0, 0));

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			PUCHAR pbHash = (PUCHAR)alloca(HashBlockLength);

			0 <= (status = BCryptHashData(hHash, const_cast<PUCHAR>(pbToBeSigned), cbToBeSigned, 0)) &&
				0 <= (status = BCryptFinishHash(hHash, pbHash, HashBlockLength, 0));

			BCryptDestroyHash(hHash);

			if (0 <= status)
			{
				BCRYPT_PKCS1_PADDING_INFO pi = { pszAlgId };

				status = BCryptSignHash(hKey, &pi, pbHash, HashBlockLength, 
					pbSignature, *pcbSignature, pcbSignature, BCRYPT_PAD_PKCS1);
			}
		}
	}

	return status;
}

inline NTSTATUS openssl_sign(_In_ BCRYPT_KEY_HANDLE hKey,
							 _In_ PCSTR szToBeSigned,
							 _Out_ PUCHAR pbSignature, 
							 _Inout_ PULONG pcbSignature,
							 _In_ PCWSTR pszAlgId)
{
	return openssl_sign(hKey, (PCUCHAR)szToBeSigned, (ULONG)strlen(szToBeSigned), pbSignature, pcbSignature, pszAlgId);
}

NTSTATUS BCryptImportKey(_Out_ BCRYPT_KEY_HANDLE *phKey, 
						 _In_ PCWSTR pszBlobType, 
						 _In_ BCRYPT_RSAKEY_BLOB* prkb, 
						 _In_ ULONG cb)
{
	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, 0, 0);

	if (0 <= status)
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, pszBlobType, phKey, (PUCHAR)prkb, cb, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

HRESULT BCryptImportPrivateKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PCUCHAR pbKey, _In_ ULONG cbKey)
{
	ULONG cb;
	PCRYPT_PRIVATE_KEY_INFO PrivateKeyInfo;

	ULONG dwError = BOOL_TO_ERROR(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, 
		pbKey, cbKey, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 0, (void**)&PrivateKeyInfo, &cb));

	if (dwError == NOERROR)
	{
		BCRYPT_RSAKEY_BLOB* prkb;

		dwError = BOOL_TO_ERROR(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
			CNG_RSA_PRIVATE_KEY_BLOB, PrivateKeyInfo->PrivateKey.pbData, PrivateKeyInfo->PrivateKey.cbData, 
			CRYPT_DECODE_ALLOC_FLAG, 0, (void**)&prkb, &cb));

		LocalFree(PrivateKeyInfo);

		if (dwError == NOERROR)
		{
			NTSTATUS status = BCryptImportKey(phKey, BCRYPT_RSAPRIVATE_BLOB, prkb, cb);
			LocalFree(prkb);
			return HRESULT_FROM_NT(status);
		}
	}

	return HRESULT_FROM_WIN32(dwError);
}

HRESULT BCryptImportPublicKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ PCUCHAR pbKeyOrCert, _In_ ULONG cbKeyOrCert, bool bCert)
{
	ULONG cb;

	union {
		PVOID pvStructInfo;
		PCERT_INFO pCertInfo;
		PCERT_PUBLIC_KEY_INFO PublicKeyInfo;
	};

	ULONG dwError = BOOL_TO_ERROR(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
		bCert ? X509_CERT_TO_BE_SIGNED : X509_PUBLIC_KEY_INFO, 
		pbKeyOrCert, cbKeyOrCert, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 0, &pvStructInfo, &cb));

	if (dwError == NOERROR)
	{
		BCRYPT_RSAKEY_BLOB* prkb;

		PVOID pv = pvStructInfo;

		if (bCert)
		{
			PublicKeyInfo = &pCertInfo->SubjectPublicKeyInfo;
		}

		dwError = BOOL_TO_ERROR(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
			CNG_RSA_PUBLIC_KEY_BLOB, 
			PublicKeyInfo->PublicKey.pbData, 
			PublicKeyInfo->PublicKey.cbData, 
			CRYPT_DECODE_ALLOC_FLAG, 0, (void**)&prkb, &cb));

		LocalFree(pv);

		if (dwError == NOERROR)
		{
			NTSTATUS status = BCryptImportKey(phKey, BCRYPT_RSAPUBLIC_BLOB, prkb, cb);
			LocalFree(prkb);
			return HRESULT_FROM_NT(status);
		}
	}

	return HRESULT_FROM_WIN32(dwError);
}

enum BLOB_TYPE { bt_priv, bt_pub, bt_cert };

HRESULT BCryptImportKey(_Out_ BCRYPT_KEY_HANDLE *phKey, _In_ BLOB_TYPE bt, _In_ PCSTR szKey, _In_ ULONG cchKey)
{
	PUCHAR pbKey = 0;
	ULONG cbKey = 0;
	HRESULT hr;

	while (CryptStringToBinaryA(szKey, cchKey, CRYPT_STRING_BASE64HEADER, pbKey, &cbKey, 0, 0))
	{
		if (pbKey)
		{
			switch (bt)
			{
			case bt_priv:
				hr = BCryptImportPrivateKey(phKey, pbKey, cbKey);
				break;
			case bt_pub:
				hr = BCryptImportPublicKey(phKey, pbKey, cbKey, false);
				break;
			case bt_cert:
				hr = BCryptImportPublicKey(phKey, pbKey, cbKey, true);
				break;
			default: hr = E_INVALIDARG;
			}

			_freea(pbKey);

			return hr;
		}

		if (!(pbKey = (PUCHAR)_malloca(cbKey)))
		{
			break;
		}
	}

	hr = HRESULT_FROM_WIN32(GetLastError());

	if (pbKey) _freea(pbKey);

	return hr;
}

HRESULT Verify_Signature(_In_ PCSTR szToBeSigned, 
						 _In_ PCSTR szPublicKeyOrCert, 
						 _In_ ULONG cchPublicKeyOrCert, 
						 _In_ PCUCHAR pbSignature, 
						 _In_ ULONG cbSignature,
						 _In_ bool bCert,
						 _In_ PCWSTR pszAlgId = BCRYPT_SHA256_ALGORITHM)
{
	HRESULT hr;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (hr = BCryptImportKey(&hKey, bCert ? bt_cert : bt_pub, szPublicKeyOrCert, cchPublicKeyOrCert)))
	{
		hr = HRESULT_FROM_NT(openssl_verify(hKey, szToBeSigned, pbSignature, cbSignature, pszAlgId));

		BCryptDestroyKey(hKey);
	}

	return hr;
}

HRESULT Create_Signature(_In_ PCSTR szToBeSigned, 
						 _In_ PCSTR szPrivateKey, 
						 _In_ ULONG cchPrivateKey,
						 _Out_ UCHAR** ppbSignature,
						 _Out_ ULONG* pcbSignature,
						 _In_ PCWSTR pszAlgId = BCRYPT_SHA256_ALGORITHM)
{
	HRESULT hr;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (hr = BCryptImportKey(&hKey, bt_priv, szPrivateKey, cchPrivateKey)))
	{
		ULONG cbSignature, cb;

		if (0 <= (hr = BCryptGetProperty(hKey, BCRYPT_SIGNATURE_LENGTH, (PUCHAR)&cbSignature, sizeof(ULONG), &cb, 0)))
		{
			if (PUCHAR pbSignature = new UCHAR[cbSignature])
			{
				if (0 <= (hr = HRESULT_FROM_NT(openssl_sign(hKey, szToBeSigned, pbSignature, &cbSignature, pszAlgId))))
				{
					*pcbSignature = cbSignature, *ppbSignature = pbSignature;
				}
				else
				{
					delete [] pbSignature;
				}
			}
		}
		BCryptDestroyKey(hKey);
	}

	return hr;
}

void testOVPN(PCSTR buf)
{
	static const CHAR TestToBeSigned[] = "Test To Be Signed";

	static const CHAR key_begin[] = "<key>";
	static const CHAR key_end[] = "</key>";

	if (PCSTR pa = strstr(buf, key_begin))
	{
		if (PCSTR pb = strstr(pa += _countof(key_begin) - 1, key_end))
		{
			PUCHAR pbSignature;
			ULONG cbSignature;

			if (0 <= Create_Signature(TestToBeSigned, pa, (ULONG)(ULONG_PTR)(pb - pa), &pbSignature, &cbSignature))
			{
				static const CHAR cert_begin[] = "<cert>";
				static const CHAR cert_end[] = "</cert>";

				if (pa = strstr(buf, cert_begin))
				{
					if (pb = strstr(pa += _countof(cert_begin) - 1, cert_end))
					{
						if (0 > Verify_Signature(TestToBeSigned, 
							pa, (ULONG)(ULONG_PTR)(pb - pa), pbSignature, cbSignature, true))
						{
							__debugbreak();
						}
					}
				}
			}
		}
	}
}

void testOVPN(PWSTR pszFile)
{
	HANDLE hFile = CreateFile(pszFile, FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		FILE_STANDARD_INFO fsi;

		if (GetFileInformationByHandleEx(hFile, FileStandardInfo, &fsi, sizeof(fsi)))
		{
			if (fsi.EndOfFile.LowPart && !fsi.EndOfFile.HighPart)
			{
				if (PSTR buf = new char[fsi.EndOfFile.LowPart+1])
				{
					if (ReadFile(hFile, buf, fsi.EndOfFile.LowPart, &fsi.EndOfFile.LowPart, 0))
					{
						buf[fsi.EndOfFile.LowPart] = 0;

						testOVPN(buf);
					}

					delete [] buf;
				}
			}
		}

		CloseHandle(hFile);
	}
}