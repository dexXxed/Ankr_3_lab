#include <Windows.h>
#include <WinCrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

using namespace std;

class descriptive_exception : public exception {
public:
	explicit descriptive_exception(const char* message) : msg_(message) {}

	char const* what() const noexcept override { return msg_; }

private:
	const char* msg_;
};

struct csp_alg_properties
{
	PROV_ENUMALGS_EX enumalgs;
	DWORD keyx_key_inc;
	DWORD sig_key_inc;
};

struct block_key_info
{
	DWORD mode;
	DWORD block_byte_size;
	BYTE* iv = nullptr;
};


void get_csp_containers(HCRYPTPROV handle, std::vector<std::string>& mas)
{
	char buff[4096];
	DWORD tmp = 4096;
	if (!CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)&buff, &tmp, CRYPT_FIRST))
		throw descriptive_exception("in start reading conainers");
	mas.push_back(buff);
	while (CryptGetProvParam(handle, PP_ENUMCONTAINERS, (BYTE*)&buff, &tmp, CRYPT_NEXT))
		mas.push_back(buff);
	if (GetLastError() != ERROR_NO_MORE_ITEMS)
		throw descriptive_exception("in reading conainers");
}

bool name_in_array(const std::string& name, const std::vector<std::string>& mas)
{
	for (const std::string& a : mas)
		if (a == name)
			return true;
	return false;
}

void get_csp_handler(DWORD csp_type, LPTSTR csp_name, const std::string keyset_name, HCRYPTPROV& handler)
{
	std::vector<std::string> containers;
	if (!CryptAcquireContext(&handler, NULL, csp_name, csp_type, 0))
	{
		if (GetLastError() == 0x80090016L)
			goto mark_create_keycase;
		else
			throw descriptive_exception("in get csp handle with 0 dwFlags");
	}
	get_csp_containers(handler, containers);
	if (name_in_array(keyset_name, containers))
	{
	mark_open_exist_keycase:
		CryptReleaseContext(handler, 0);
		if (!CryptAcquireContext(&handler, (LPCWSTR) keyset_name.c_str(), csp_name, csp_type, 0))
			throw descriptive_exception("in get csp handle with exist key container");
		containers.clear();
		get_csp_containers(handler, containers);
	}
	else
	{
	mark_create_keycase:
		cout << "ctreate " << keyset_name << " keycontainer" << endl;
		CryptReleaseContext(handler, 0);
		if (!CryptAcquireContext(&handler, (LPCWSTR) keyset_name.c_str(), csp_name, csp_type, CRYPT_NEWKEYSET))
		{
			if (GetLastError() == 0x8009000FL)
			{
				//cout << "Key set " << keyset_name << " is already exist, try open" << endl;
				goto mark_open_exist_keycase;
			}
			else
				throw descriptive_exception("in get csp handle with create key container");
		}
	}
}

void get_alg_properties(HCRYPTPROV handler, DWORD alg_id, csp_alg_properties& param)
{
	DWORD dword_size = sizeof(DWORD);
	DWORD param_size = sizeof(param.enumalgs);
	if (!CryptGetProvParam(handler, PP_ENUMALGS_EX, (BYTE*)&param.enumalgs, &param_size, CRYPT_FIRST))
		throw descriptive_exception("in start reading algorithms");
	if (!CryptGetProvParam(handler, PP_KEYX_KEYSIZE_INC, (BYTE*)&param.keyx_key_inc, &dword_size, 0))
		throw descriptive_exception("in start reading keyx_inc");
	if (!CryptGetProvParam(handler, PP_SIG_KEYSIZE_INC, (BYTE*)&param.sig_key_inc, &dword_size, 0))
		throw descriptive_exception("in start reading sig_inc");
	if (param.enumalgs.aiAlgid == alg_id)
		return;
	while (CryptGetProvParam(handler, PP_ENUMALGS_EX, (BYTE*)&param.enumalgs, &param_size, CRYPT_NEXT))
	{
		if (param.enumalgs.aiAlgid == alg_id)
			return;
	}
	DWORD error = GetLastError();
	if (error != ERROR_NO_MORE_ITEMS)
		throw descriptive_exception("in reading algorithms");
	throw descriptive_exception("algorithm_id was not found");
}

DWORD get_key_len(DWORD min, DWORD max, DWORD delta, DWORD k)
{
	DWORD mod = (max - min) / delta + 1;
	k %= mod;
	return min + k * delta;
}

void gen_exchange_key(HCRYPTPROV csp_handler, DWORD alg_id, DWORD k, HCRYPTKEY& key_handler)
{
	csp_alg_properties alg_prop;
	get_alg_properties(csp_handler, alg_id, alg_prop);
	DWORD keylen = get_key_len(alg_prop.enumalgs.dwMinLen, alg_prop.enumalgs.dwMaxLen, alg_prop.keyx_key_inc, k);
	DWORD flags = keylen << 16;
	flags |= CRYPT_EXPORTABLE;
	flags |= CRYPT_USER_PROTECTED;
	if (!CryptGenKey(csp_handler, alg_id, flags, &key_handler))
		throw descriptive_exception("in key create");
}


void set_key_info(HCRYPTKEY key_handler, const block_key_info& info)
{
	if (!CryptSetKeyParam(key_handler, KP_MODE, (BYTE*)&(info.mode), 0))
		throw descriptive_exception("in set key mode");
	if (!CryptSetKeyParam(key_handler, KP_IV, info.iv, 0))
		throw descriptive_exception("in set key iv");
}

void gen_sblock_key(HCRYPTPROV csp_handler, DWORD alg_id, HCRYPTKEY& key_handler, DWORD mode)
{
	csp_alg_properties alg_prop;
	get_alg_properties(csp_handler, alg_id, alg_prop);
	DWORD keylen = alg_prop.enumalgs.dwMaxLen;
	DWORD flags = keylen << 16;
	flags |= CRYPT_EXPORTABLE;
	flags |= CRYPT_USER_PROTECTED;
	if (!CryptGenKey(csp_handler, alg_id, flags, &key_handler))
		throw descriptive_exception("in key create");
	block_key_info info;
	info.mode = mode;
	DWORD dword_size = sizeof(DWORD);
	if (!CryptGetKeyParam(key_handler, KP_BLOCKLEN, (BYTE*)&(info.block_byte_size), &dword_size, 0))
		throw descriptive_exception("in get key block size");
	info.iv = new BYTE[info.block_byte_size];
	if (!CryptGenRandom(csp_handler, info.block_byte_size, info.iv))
		throw descriptive_exception("in gen iv");
	set_key_info(key_handler, info);
	delete[] info.iv;
}

void get_key_info(HCRYPTKEY key_handler, block_key_info& info)
{
	DWORD dword_size = sizeof(DWORD);
	if (!CryptGetKeyParam(key_handler, KP_MODE, (BYTE*)&(info.mode), &dword_size, 0))
		throw descriptive_exception("in get key mode");
	if (!CryptGetKeyParam(key_handler, KP_BLOCKLEN, (BYTE*)&(info.block_byte_size), &dword_size, 0))
		throw descriptive_exception("in get key block size");
	info.block_byte_size /= 8;
	info.iv = new BYTE[info.block_byte_size];
	if (!CryptGetKeyParam(key_handler, KP_IV, info.iv, &(info.block_byte_size), 0))
		throw descriptive_exception("in get key block");
}

void export_key(HCRYPTKEY key_handler, HCRYPTKEY expkey_handler, const char* filename)
{
	DWORD blob_size;
	if (!CryptExportKey(key_handler, expkey_handler, SIMPLEBLOB, 0, NULL, &blob_size))
		throw descriptive_exception("in get blob size");
	BYTE* blob = new BYTE[blob_size];
	if (!CryptExportKey(key_handler, expkey_handler, SIMPLEBLOB, 0, blob, &blob_size))
		throw descriptive_exception("in get blob");
	FILE* f = fopen(filename, "wb");
	if (!f) throw descriptive_exception("in open file to write");
	if (fwrite(&blob_size, 1, sizeof(blob_size), f) != sizeof(blob_size))
		throw descriptive_exception("in writing to file");
	if (fwrite(blob, 1, blob_size, f) != blob_size)
		throw descriptive_exception("in writing to file");
	delete[] blob;
	block_key_info info;
	get_key_info(key_handler, info);
	if (fwrite(&(info.mode), 1, sizeof(info.mode), f) != sizeof(info.mode))
		throw descriptive_exception("in writing to file");
	if (fwrite(&(info.block_byte_size), 1, sizeof(info.block_byte_size), f) != sizeof(info.block_byte_size))
		throw descriptive_exception("in writing to file");
	if (fwrite(info.iv, 1, info.block_byte_size, f) != info.block_byte_size)
		throw descriptive_exception("in writing to file");
	fclose(f);
}

void import_key(HCRYPTPROV csp_handler, HCRYPTKEY impkey_handler, const char* filename, HCRYPTKEY& key_handler)
{
	FILE* f = fopen(filename, "rb");
	if (!f) throw descriptive_exception("in open file to read");
	DWORD blob_size;
	if (fread(&blob_size, 1, sizeof(blob_size), f) != sizeof(blob_size))
		throw descriptive_exception("in reading from file");
	BYTE* blob = new BYTE[blob_size];
	if (fread(blob, 1, blob_size, f) != blob_size)
		throw descriptive_exception("in reading from file");
	if (!CryptImportKey(csp_handler, blob, blob_size, impkey_handler, 0, &key_handler))
		throw descriptive_exception("in importing key");
	delete[] blob;
	block_key_info info;
	if (fread(&(info.mode), 1, sizeof(info.mode), f) != sizeof(info.mode))
		throw descriptive_exception("in reading from file");
	if (fread(&(info.block_byte_size), 1, sizeof(info.block_byte_size), f) != sizeof(info.block_byte_size))
		throw descriptive_exception("in reading from file");
	info.iv = new BYTE[info.block_byte_size];
	if (fread(info.iv, 1, info.block_byte_size, f) != info.block_byte_size)
		throw descriptive_exception("in reading from file");
	set_key_info(key_handler, info);
	delete[] info.iv;
}


void encrypt_file(HCRYPTKEY key_handler, const char* file_in, const char* file_out)
{
	DWORD data_block_size = 1024;
	DWORD buff_size = data_block_size + 128;
	BYTE* buff = new BYTE[buff_size];
	FILE* fin = fopen(file_in, "rb");
	if (!fin) throw descriptive_exception("open file to read");
	FILE* fout = fopen(file_out, "wb");
	if (!fout) throw descriptive_exception("open file to write");
	DWORD cur_len;
	while (cur_len = fread(buff, 1, data_block_size, fin))
	{
		if (!CryptEncrypt(key_handler, NULL, (cur_len == data_block_size ? FALSE : TRUE), 0, buff, &cur_len, buff_size))
			throw descriptive_exception("encryption data");
		fwrite(buff, 1, cur_len, fout);
	}
	fclose(fin);
	fclose(fout);
	delete[] buff;
}

void decrypt_file(HCRYPTKEY key_handler, const char* file_in, const char* file_out)
{
	DWORD data_block_size = 1024;
	DWORD buff_size = data_block_size + 128;
	BYTE* buff = new BYTE[buff_size];
	FILE* fin = fopen(file_in, "rb");
	if (!fin) throw descriptive_exception("open file to read");
	FILE* fout = fopen(file_out, "wb");
	if (!fout) throw descriptive_exception("open file to write");
	DWORD cur_len;
	while (cur_len = fread(buff, 1, data_block_size, fin))
	{
		if (!CryptDecrypt(key_handler, NULL, (cur_len == data_block_size ? FALSE : TRUE), 0, buff, &cur_len))
			throw descriptive_exception("decryption data");
		fwrite(buff, 1, cur_len, fout);
	}
	fclose(fin);
	fclose(fout);
	delete[] buff;
}


int main(int argc, const char** argv)
{
	DWORD csp_type = PROV_RSA_AES;
	auto csp_name = (LPTSTR) MS_ENH_RSA_AES_PROV;
	DWORD k = 11;
	std::string keyset_name = "dexxxed";
	DWORD alg_sblock_id = 26128; // AES 256-bit
	HCRYPTPROV csp_handler = 0;
	HCRYPTKEY key_exchange_handler = 0;
	if (argc == 1)
	{
		cout << "So, welcome to help!" << endl;
		cout << "Bad using, use one of the options below:" << endl;
		cout << "ankr_3_lab.exe gen [mode (cbc, ecb, cfb)] [key_file]" << endl;
		cout << "ankr_3_lab.exe encrypt [key_file] [file_in] [file_out]" << endl;
		cout << "ankr_3_lab.exe decrypt [key_file] [file_in] [file_out]" << endl;
		return -1;
	}
	try
	{
		get_csp_handler(csp_type, csp_name, keyset_name, csp_handler);
		if (!strcmp(argv[1], "gen"))
		{
			DWORD mode;
			if (!strcmp(argv[2], "cbc"))
				mode = CRYPT_MODE_CBC;
			else if (!strcmp(argv[2], "ecb"))
				mode = CRYPT_MODE_ECB;
			//else if (!strcmp(argv[2], "ofb"))
			//	mode = CRYPT_MODE_OFB;
			else if (!strcmp(argv[2], "cfb"))
				mode = CRYPT_MODE_CFB;
			//else if (!strcmp(argv[2], "cts"))
			//	mode = CRYPT_MODE_CTS;
			else
				throw descriptive_exception("bad 2 argument");
			HCRYPTKEY key_handler, expkey_handler;
			gen_sblock_key(csp_handler, alg_sblock_id, key_handler, mode);
			if (!CryptGetUserKey(csp_handler, AT_KEYEXCHANGE, &expkey_handler))
				throw descriptive_exception("get exchange key");
			export_key(key_handler, expkey_handler, argv[3]);
		}
		else if (!strcmp(argv[1], "encrypt"))
		{
			HCRYPTKEY key_handler, impkey_handler;
			if (!CryptGetUserKey(csp_handler, AT_KEYEXCHANGE, &impkey_handler))
				throw descriptive_exception("get exchange key");
			import_key(csp_handler, impkey_handler, argv[2], key_handler);
			encrypt_file(key_handler, argv[3], argv[4]);
		}
		else if (!strcmp(argv[1], "decrypt"))
		{
			HCRYPTKEY key_handler, impkey_handler;
			if (!CryptGetUserKey(csp_handler, AT_KEYEXCHANGE, &impkey_handler))
				throw descriptive_exception("get exchange key");
			import_key(csp_handler, impkey_handler, argv[2], key_handler);
			decrypt_file(key_handler, argv[3], argv[4]);
		}
		else
			throw descriptive_exception("bad 1 argument");
	}
	catch (exception & error) {
		cout << "Error message: " << error.what() << endl;
		cout << "System Error Code: " << GetLastError() << endl;
		cout << "You can read more about System Error Codes here:" <<
			"https://docs.microsoft.com/ru-ru/windows/win32/debug/system-error-codes" << endl;
		system("PAUSE");
		return -1;
	}
	return 0;
}
