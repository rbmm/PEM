#include "stdafx.h"

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

ULONG CryptImportPublicKey(_Out_ HCRYPTKEY *phKey, 
						   _In_ HCRYPTPROV hProv,
						   _In_ PCUCHAR pbKeyOrCert, 
						   _In_ ULONG cbKeyOrCert, 
						   _In_ bool bCert)
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
		PVOID pv = pvStructInfo;

		if (bCert)
		{
			PublicKeyInfo = &pCertInfo->SubjectPublicKeyInfo;
		}

		dwError = BOOL_TO_ERROR(CryptImportPublicKeyInfo(hProv, 
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PublicKeyInfo, phKey));

		LocalFree(pv);
	}

	return dwError;
}

ULONG CryptImportPrivateKey(_Out_ HCRYPTKEY* phKey, 
							_In_ HCRYPTPROV hProv, 
							_In_ PCUCHAR pbKey, 
							_In_ ULONG cbKey)
{
	ULONG cb;
	PCRYPT_PRIVATE_KEY_INFO PrivateKeyInfo;

	ULONG dwError = BOOL_TO_ERROR(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO, 
		pbKey, cbKey, CRYPT_DECODE_ALLOC_FLAG|CRYPT_DECODE_NOCOPY_FLAG, 0, (void**)&PrivateKeyInfo, &cb));

	if (dwError == NOERROR)
	{
		PUBLICKEYSTRUC* ppks;  

		dwError = BOOL_TO_ERROR(CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 
			PKCS_RSA_PRIVATE_KEY, PrivateKeyInfo->PrivateKey.pbData, PrivateKeyInfo->PrivateKey.cbData, 
			CRYPT_DECODE_ALLOC_FLAG, 0, (void**)&ppks, &cb));

		LocalFree(PrivateKeyInfo);

		if (dwError == NOERROR)
		{
			dwError = BOOL_TO_ERROR(CryptImportKey(hProv, (PUCHAR)ppks, cb, 0, CRYPT_EXPORTABLE, phKey));
			LocalFree(ppks);
		}
	}

	return dwError;
}

enum BLOB_TYPE { bt_priv, bt_pub, bt_cert };

ULONG CryptImportKey(_Out_ HCRYPTKEY *phKey, 
					 _In_ HCRYPTPROV hProv,
					 _In_ BLOB_TYPE bt, 
					 _In_ PCSTR szKey, 
					 _In_ ULONG cchKey)
{
	PUCHAR pbKey = 0;
	ULONG cbKey = 0;
	ULONG dwError;

	while (CryptStringToBinaryA(szKey, cchKey, CRYPT_STRING_BASE64HEADER, pbKey, &cbKey, 0, 0))
	{
		if (pbKey)
		{
			switch (bt)
			{
			case bt_priv:
				dwError = CryptImportPrivateKey(phKey, hProv, pbKey, cbKey);
				break;
			case bt_pub:
				dwError = CryptImportPublicKey(phKey, hProv, pbKey, cbKey, false);
				break;
			case bt_cert:
				dwError = CryptImportPublicKey(phKey, hProv, pbKey, cbKey, true);
				break;
			default: dwError = ERROR_INVALID_PARAMETER;
			}

			_freea(pbKey);

			return dwError;
		}

		if (!(pbKey = (PUCHAR)_malloca(cbKey)))
		{
			break;
		}
	}

	dwError = GetLastError();

	if (pbKey) _freea(pbKey);

	return dwError;
}

void DoLegacyTest(_In_ PCSTR szToBeSigned, 
				  _In_ PCSTR szPrivateKey, 
				  _In_ ULONG cchPrivateKey,
				  _In_ PCSTR szPublicKeyOrCert, 
				  _In_ ULONG cchPublicKeyOrCert,
				  _In_ bool bCert)
{
	HCRYPTPROV hProv;
	if (CryptAcquireContextW(&hProv, 0, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		HCRYPTKEY hKey;
		HCRYPTHASH hHash;

		if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
		{
			if (CryptHashData(hHash, (PUCHAR)szToBeSigned, (ULONG)strlen(szToBeSigned), 0))
			{
				PUCHAR pbSignature = 0;
				ULONG cbSignature = 0;
				BOOL fOk = false;

				if (NOERROR == CryptImportKey(&hKey, hProv, bt_priv, szPrivateKey, cchPrivateKey))
				{
					ULONG dwKeySpec, cb; 

					if (CryptGetKeyParam(hKey, KP_ALGID, (PUCHAR)&dwKeySpec, &(cb = sizeof(dwKeySpec)), 0))
					{
						switch (dwKeySpec)
						{
						case CALG_RSA_KEYX:
							dwKeySpec = AT_KEYEXCHANGE;
							break;
						case CALG_RSA_SIGN:
							dwKeySpec = AT_SIGNATURE;
							break;
						default: dwKeySpec = 0;
						}

						if (CryptGetKeyParam(hKey, KP_BLOCKLEN, (PUCHAR)&cbSignature, &(cb = sizeof(cbSignature)), 0))
						{
							pbSignature = (PUCHAR)alloca(cbSignature >>= 3);

							fOk = CryptSignHashW(hHash, dwKeySpec, 0, 0, pbSignature, &cbSignature);
						}
					}

					CryptDestroyKey(hKey);
				}

				if (fOk)
				{
					if (NOERROR == CryptImportKey(&hKey, hProv, bCert ? bt_cert : bt_pub, szPublicKeyOrCert, cchPublicKeyOrCert))
					{
						if (!CryptVerifySignatureW(hHash, pbSignature, cbSignature, hKey, 0, 0))
						{
							__debugbreak();
						}
						CryptDestroyKey(hKey);
					}
				}
			}

			CryptDestroyHash(hHash);
		}

		CryptReleaseContext(hProv, 0);
	}
}

void testOVPN(PCSTR buf)
{
	static const CHAR key_begin[] = "<key>";
	static const CHAR key_end[] = "</key>";
	static const CHAR cert_begin[] = "<cert>";
	static const CHAR cert_end[] = "</cert>";

	if (PCSTR px = strstr(buf, key_begin))
	{
		if (PCSTR py = strstr(px += _countof(key_begin) - 1, key_end))
		{
			if (PCSTR pa = strstr(buf, cert_begin))
			{
				if (PCSTR pb = strstr(pa += _countof(cert_begin) - 1, cert_end))
				{
					DoLegacyTest("Test To Be Signed",
						px, (ULONG)(ULONG_PTR)(py - px),
						pa, (ULONG)(ULONG_PTR)(pb - pa),
						true);
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