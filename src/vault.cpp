#include "vault.h"

#include <stddef.h>

#include "sha3/sha3.h"
#include "plat.h"

// SHA-2 init hash constants
#define ENCRYPT_KEY_CONSTANT  0xbb67ae856a09e667ULL
#define COLOR_KEY_CONSTANT    0xa54ff53a3c6ef372ULL
#define LOCDIR_KEY_CONSTANT   0x9b05688c510e527fULL
#define HEADER_KEY_CONSTANT   0x5be0cd191f83d9abULL

#define SECRET_KEY_CONSTANT   0x71374491428a2f98ULL

#include <fstream>
#include <filesystem>
#include <bit>

#define BYTESWAP16(x) ((((x)&0xFF)<<8) | (((x)&0xFF00)>>8))
#define BYTESWAP32(x) ((((x)&0xFF)<<24) | (((x)&0xFF00)<<8) | (((x)&0xFF0000)>>8) | (((x)&0xFF000000)>>24))
#define BYTESWAP64(x) ((((x)&0xFFULL)<<56) | (((x)&0xFF00ULL)<<40) | (((x)&0xFF0000ULL)<<24) | (((x)&0xFF000000ULL)<<8) | \
					   (((x)&0xFF00000000ULL)>>8) | (((x)&0xFF0000000000ULL)>>24) | (((x)&0xFF000000000000ULL)>>40) | (((x)&0xFF00000000000000ULL)>>56))

namespace fs = std::filesystem;

static_assert(BYTESWAP64(BYTESWAP64(LOCDIR_KEY_CONSTANT))==LOCDIR_KEY_CONSTANT);
static_assert(BYTESWAP32(BYTESWAP32((u32)LOCDIR_KEY_CONSTANT))==(u32)LOCDIR_KEY_CONSTANT);
static_assert(BYTESWAP16(BYTESWAP16((u16)LOCDIR_KEY_CONSTANT))==(u16)LOCDIR_KEY_CONSTANT);

extern bool gDebug;

void TruncateString(std::string& str){
	while (!str.empty()&&(str.front()==' '||str.front()=='\t')){
		str.erase(0,1);
	}
	while (!str.empty()&&(str.back()==' '||str.back()=='\t')){
		str.pop_back();
	}
}

Sha3State GenerateKey(Sha3State salted,u64 keyType){
	salted.UpdateU64(keyType);
	salted.Rehash(MINOR_HASH_ROUNDS);
	return salted;
}

Sha3State InitKey(const std::string& pass,u64 salt){
	Sha3State k{};
	k.UpdateString(pass);
	k.UpdateU64(salt);
	k.Rehash(MASTER_HASH_ROUNDS);
	return k;
}

SecretString Secret::GetPass(Sha3State key){
	Sha3State keyClone = GenerateKey(key,SECRET_KEY_CONSTANT);
	keyClone.UpdateU16((u16)type);
	keyClone.UpdateU64(genTime);
	keyClone.UpdateU32(options.length);
	keyClone.Rehash(SUB_HASH_ROUNDS);
	
	HashResult& res = keyClone.result;
	
	SecretString pass{};
	
	u32 count = options.length;
	u32 bits = 0;
	u32 index = 0;
	u8 c;
	for (u32 i=0;i<count;++i){
		c = ((res[index]>>bits) | (res[index+1]<<(8-bits)))&63;
		
		bits += 6;
		if (bits>=8){
			index += 1;
			bits -= 8;
		}
		if (index>=(HASH_BYTES-1)&&bits>=6){
			// recalc state for more
			keyClone.Rehash(1);
			index = 0;
			bits = 0;
		}
		
		pass.push_back(passwordChars[c]);
	}
	
	return pass;
}

struct BufferWriteCtx {
	std::fstream& out;
	
	void Write(const u8* data,size_t count){
		out.write((const char*)data,count);
	}
	
	void WriteU32(u32 num){
		if constexpr (std::endian::native != std::endian::little){
			u32 val = BYTESWAP32(num);
			Write((u8*)&val,sizeof(u32));
		} else {
			Write((u8*)&num,sizeof(u32));
		}
	}
	
	void WriteU64(u64 num){
		if constexpr (std::endian::native != std::endian::little){
			u64 val = BYTESWAP64(num);
			Write((u8*)&val,sizeof(u64));
		} else {
			Write((u8*)&num,sizeof(u64));
		}
	}
	
	void WritePlainHeader(u64 salt){
		static_assert(sizeof(VAULT_MAGIC)==4);
		
		Write(VAULT_MAGIC,sizeof(VAULT_MAGIC));
		WriteU32(VERSION_NUMBER);
		WriteU64(salt);
	}
};

struct BufferEncryptCtx {
	std::fstream& out;
	Sha3State& key;
	u32 keyBytes = 0;
	
	void Encrypt(const u8* data,size_t count){
		for (size_t i=0;i<count;++i){
			out.put(data[i]^key.result[keyBytes]);
			++keyBytes;
			if (keyBytes>=HASH_BYTES){
				key.Rehash(1);
				keyBytes -= HASH_BYTES;
			}
		}
	}
	
	void EncryptU64(u64 num){
		if constexpr (std::endian::native != std::endian::little){
			u64 val = BYTESWAP64(num);
			Encrypt((u8*)&val,sizeof(u64));
		} else {
			Encrypt((u8*)&num,sizeof(u64));
		}
	}
	
	void EncryptU32(u32 num){
		if constexpr (std::endian::native != std::endian::little){
			u32 val = BYTESWAP32(num);
			Encrypt((u8*)&val,sizeof(u32));
		} else {
			Encrypt((u8*)&num,sizeof(u32));
		}
	}
	
	void EncryptU16(u16 num){
		if constexpr (std::endian::native != std::endian::little){
			u16 val = BYTESWAP16(num);
			Encrypt((u8*)&val,sizeof(u16));
		} else {
			Encrypt((u8*)&num,sizeof(u16));
		}
	}
	
	void EncryptU8(u8 num){
		Encrypt(&num,sizeof(u8));
	}
	
	void EncryptString(const std::string& str){
		EncryptU64(str.size());
		Encrypt((const u8*)str.data(),str.size());
	}
	
	void EncryptShortString(const std::string& str,bool extraBit=false){
		u8 size = str.size() | (extraBit<<7);
		EncryptU8(size);
		Encrypt((const u8*)str.data(),str.size()&0x7F);
	}
		
	void EncryptFileDescriptor(const FileDescriptor& header){
		bool mini = header.location.offset<=0xFFFF && header.location.size<=0xFFFF;
		EncryptShortString(header.name,mini);
		EncryptU32(header.salt);
		EncryptU16((u16)header.type);
		EncryptU64(header.genTime);
		if (mini){
			EncryptU16(header.location.offset);
			EncryptU16(header.location.size);
		} else {
			EncryptU64(header.location.offset);
			EncryptU64(header.location.size);
		}
	}
	
	void EncryptDirectory(const Directory& dir){
		bool mini = dir.dirs.size()<=0xFF && dir.files.size()<=0xFF;
		EncryptShortString(dir.name,mini);
		
		if (mini){
			EncryptU8(dir.dirs.size());
			EncryptU8(dir.files.size());
		} else {
			EncryptU64(dir.dirs.size());
			EncryptU64(dir.files.size());
		}
		
		for (const auto& subdir : dir.dirs){
			EncryptDirectory(subdir);
		}
		
		for (const auto& file : dir.files){
			EncryptFileDescriptor(file);
		}
	}
	
	void EncryptLocationDirectory(const LocationDirectory& locs){
		EncryptDirectory(locs.root);
	}
	
	void EncryptVaultHeader(u64 locDirSize){
		u8 zeroes[ZERO_VECTOR_SIZE];
		memset(zeroes,0,ZERO_VECTOR_SIZE);
		
		Encrypt(zeroes,ZERO_VECTOR_SIZE);
		EncryptU64(locDirSize);
	}
};

struct BufferReadCtx {
	std::fstream& in;
	
	void Read(u8* data,size_t count){
		in.read((char*)data,count);
	}
	
	void ReadU32(u32& num){
		if constexpr (std::endian::native != std::endian::little){
			Read((u8*)&num,sizeof(u32));
			num = BYTESWAP32(num);
		} else {
			Read((u8*)&num,sizeof(u32));
		}
	}
	
	void ReadU64(u64& num){
		if constexpr (std::endian::native != std::endian::little){
			Read((u8*)&num,sizeof(u64));
			num = BYTESWAP64(num);
		} else {
			Read((u8*)&num,sizeof(u64));
		}
	}
	
	void ReadPlainHeader(PlainHeader& header){
		Read(&header.magic[0],sizeof(VAULT_MAGIC));
		ReadU32(header.version);
		ReadU64(header.salt);
	}
	
	void SeekToHeaderPos(){
		in.seekg(PLAIN_HEADER_OFFSET,std::ios::end);
	}
};

struct BufferDecryptCtx {
	std::fstream& in;
	Sha3State& key;
	u32 keyBytes = 0;
	
	void Decrypt(u8* data,size_t count){
		char c;
		for (size_t i=0;i<count;++i){
			in.get(c);
			data[i] = c^key.result[keyBytes];
			
			++keyBytes;
			if (keyBytes>=HASH_BYTES){
				key.Rehash(1);
				keyBytes -= HASH_BYTES;
				
			}
		}
	}
	
	void DecryptU64(u64& num){
		if constexpr (std::endian::native != std::endian::little){
			Decrypt((u8*)&num,sizeof(u64));
			num = BYTESWAP64(num);
		} else {
			Decrypt((u8*)&num,sizeof(u64));
		}
	}
	
	void DecryptU32(u32& num){
		if constexpr (std::endian::native != std::endian::little){
			Decrypt((u8*)&num,sizeof(u32));
			num = BYTESWAP32(num);
		} else {
			Decrypt((u8*)&num,sizeof(u32));
		}
	}
	
	void DecryptU16(u16& num){
		if constexpr (std::endian::native != std::endian::little){
			Decrypt((u8*)&num,sizeof(u16));
			num = BYTESWAP16(num);
		} else {
			Decrypt((u8*)&num,sizeof(u16));
		}
	}
	
	void DecryptU8(u8& num){
		Decrypt(&num,sizeof(u8));
	}
	
	void DecryptString(std::string& str){
		size_t size;
		DecryptU64(size);
		str.resize(size);
		u8* d = (u8*)str.data();
		Decrypt(d,size);
	}
	
	void DecryptShortString(std::string& str,bool& extraBit){
		u8 size;
		DecryptU8(size);
		extraBit = size&(1<<7);
		size &= 0x7F;
		str.resize(size);
		Decrypt((u8*)str.data(),size);
	}
	
	bool DecryptFile(File& file,u64 size){
		u8 magic[sizeof(FILE_MAGIC)];
		Decrypt(&magic[0],sizeof(FILE_MAGIC));
		
		if (memcmp(magic,FILE_MAGIC,sizeof(FILE_MAGIC))!=0){
			return false;
		}
		
		file.data.resize(size);
		Decrypt(file.data.data(),size);
		
		return true;
	}
	
	void DecryptFileDescriptor(FileDescriptor& header){
		bool mini;
		DecryptShortString(header.name,mini);
		DecryptU32(header.salt);
		u16 type;
		DecryptU16(type);
		header.type = (FileType)type;
		DecryptU64(header.genTime);
		if (mini){
			u16 smallOffset,smallSize;
			DecryptU16(smallOffset);
			DecryptU16(smallSize);
			header.location.offset = smallOffset;
			header.location.size = smallSize;
		} else {
			DecryptU64(header.location.offset);
			DecryptU64(header.location.size);
		}
	}
	
	void DecryptDirectory(Directory& dir){
		bool mini;
		DecryptShortString(dir.name,mini);
		
		u64 dirCount;
		u64 fileCount;
		
		if (mini){
			u8 smallDirCount;
			u8 smallFileCount;
			DecryptU8(smallDirCount);
			DecryptU8(smallFileCount);
			dirCount = smallDirCount;
			fileCount = smallFileCount;
		} else {
			DecryptU64(dirCount);
			DecryptU64(fileCount);
		}
		
		dir.dirs = {};
		dir.files = {};
		
		Directory sub;
		for (u64 i=0;i<dirCount;++i){
			sub.parent = &dir;
			dir.dirs.push_back(sub);
			DecryptDirectory(dir.dirs.back());
		}
		
		FileDescriptor desc;
		for (u64 i=0;i<fileCount;++i){
			DecryptFileDescriptor(desc);
			dir.AddFile(desc);
		}
	}
	
	void DecryptLocationDirectory(LocationDirectory& locs){
		DecryptDirectory(locs.root);
	}
	
	void DecryptVaultHeader(VaultHeader& header){
		Decrypt(header.zeroes,ZERO_VECTOR_SIZE);
		DecryptU64(header.locDirSize);
	}
};

void File::WriteU64(u64 num){
	for (u64 i=0;i<sizeof(u64);++i){
		data.push_back(num&0xFF);
		num >>= 8;
	}
}

u64 File::ReadU64(){
	u64 num = 0;
	for (u64 i=0;i<sizeof(u64);++i){
		num |= data[readHead++]<<(i*8);
	}
	return num;
}

void File::WriteU32(u32 num){
	for (u64 i=0;i<sizeof(u32);++i){
		data.push_back(num&0xFF);
		num >>= 8;
	}
}

u32 File::ReadU32(){
	u32 num = 0;
	for (u64 i=0;i<sizeof(u32);++i){
		num |= data[readHead++]<<(i*8);
	}
	return num;
}

u64 Directory::GetBiggestNameSize() const {
	u64 s = 0;
	for (const auto& dir : dirs){
		if (dir.name.size()>s){
			s = dir.name.size();
		}
	}
	for (const auto& file : files){
		if (file.name.size()>s){
			s = file.name.size();
		}
	}
	
	return s;
}

void Directory::FixPointers(){
	for (auto& dir : dirs){
		dir.parent = this;
		dir.FixPointers();
	}
	
	for (auto& file : files){
		file.parent = this;
	}
}

void Directory::AddSize(s64 size){
	recursiveSize += size;
	if (parent){
		parent->AddSize(size);
	}
}

void Directory::AddFile(FileDescriptor desc){
	desc.parent = this;
	files.push_back(desc);
	AddSize(desc.location.size+FILE_HEADER_SIZE);
}

void Directory::DeleteFile(FileDescriptor& delFile){
	auto it = files.begin();
	for (auto& file : files){
		if (&file==&delFile){
			break;
		}
		++it;
	}
	
	if (it!=files.end()){
		AddSize(-(delFile.location.size+FILE_HEADER_SIZE));
		files.erase(it);
	}
}

void Directory::CreateDir(const SecretString& name){
	Directory d{name};
	d.parent = this;
	d.recursiveSize = 0;
	dirs.push_back(d);
}

void Directory::UnlinkDir(Directory& subDir){
	auto it = dirs.begin();
	for (auto& dir : dirs){
		if (&dir==&subDir){
			break;
		}
		++it;
	}
	
	if (it!=dirs.end()){
		AddSize(-it->recursiveSize);
		dirs.erase(it);
	}
}

void Directory::LinkDir(Directory& dirToLink){
	AddSize(dirToLink.recursiveSize);
	
	dirs.push_back(dirToLink);
	auto& newDir = dirs.back();
	
	newDir.parent = this;
	newDir.FixPointers();
}

void Directory::UnlinkFile(FileDescriptor& desc){
	auto it = files.begin();
	for (auto& file : files){
		if (&file==&desc){
			break;
		}
		++it;
	}
	
	if (it!=files.end()){
		AddSize(-(it->location.size+FILE_HEADER_SIZE));
		files.erase(it);
	}
}

void Directory::LinkFile(FileDescriptor& desc){
	AddFile(desc);
}

void Directory::ShrinkFilesAfter(u64 offset,u64 amount){
	for (auto& dir : dirs){
		dir.ShrinkFilesAfter(offset,amount);
	}
	
	for (auto& file : files){
		if (file.location.offset>offset){
			file.location.offset -= amount;
		}
	}
}

bool Directory::NameIsTaken(const SecretString& name) const {
	for (const auto& dir : dirs){
		if (dir.name==name) return true;
	}
	
	for (const auto& file : files){
		if (file.name==name) return true;
	}
	
	return false;
}

u64 Directory::CountFiles() const {
	u64 count = files.size();
	for (const auto& dir : dirs){
		count += dir.CountFiles();
	}
	
	return count;
}

FilePointer Vault::GetFile(const FileDescriptor& desc){
	FilePointer fp = std::make_unique<File>();
	vaultFile.seekg(desc.location.offset);
	
	Sha3State encryptCopy = encryptKey;
	encryptCopy.UpdateU64(desc.genTime);
	encryptCopy.UpdateU32(desc.salt);
	
	BufferDecryptCtx ctx{vaultFile,encryptCopy};
	if (!ctx.DecryptFile(*fp,desc.location.size)) return nullptr;
	
	fp->readHead = 0;
	return fp;
}

// sets header.location
void Vault::AddFile(const File& file,FileDescriptor& desc){
	desc.genTime = GetTime();
	u64 salt;
	GenerateSalt(salt);
	desc.salt = (u32)salt;
	
	WriteFileAtEnd(file,desc);
	desc.location.offset = fileBlockEnd;
	desc.location.size = file.data.size();
	fileBlockEnd += desc.location.size+FILE_HEADER_SIZE;
	
	currentDir->AddFile(desc);
	WriteDirectoryAndHeader();
}

// deletes the file from the file block table without 
// deleting it from the location directory
void Vault::DeleteFileRaw(FileDescriptor& delFile){
	FileLocation loc = delFile.location;
	// copy data to close gap
	std::vector<char> buffer{};
	
	u64 writeDist = fileBlockEnd-(loc.offset+loc.size+FILE_HEADER_SIZE);
	buffer.resize(writeDist);
	
	vaultFile.seekg(loc.offset+loc.size+FILE_HEADER_SIZE);
	vaultFile.read(buffer.data(),writeDist);
	
	vaultFile.seekp(loc.offset);
	vaultFile.write(buffer.data(),writeDist);
	
	std::fill(buffer.begin(),buffer.end(),0);
	
	fileBlockEnd -= loc.size+FILE_HEADER_SIZE;
	directory.root.ShrinkFilesAfter(loc.offset,loc.size+FILE_HEADER_SIZE);
}

// deletes a file in the current directory
void Vault::DeleteFile(FileDescriptor& delFile){
	DeleteFileRaw(delFile);
	currentDir->DeleteFile(delFile);
	WriteDirectoryAndHeader();
}

void Vault::CreateDir(const SecretString& name){
	currentDir->CreateDir(name);
	WriteDirectoryAndHeader();
}

void Vault::DeleteRecursive(Directory& delDir){
	for (auto& dir : delDir.dirs){
		DeleteRecursive(dir);
	}
	
	for (auto& file : delDir.files){
		delDir.AddSize(-(file.location.size+FILE_HEADER_SIZE));
		DeleteFileRaw(file);
	}
}

// dir is guaranteed to be a child of currentDir
void Vault::DeleteDir(Directory& delDir){
	auto it = currentDir->dirs.begin();
	for (auto& dir : currentDir->dirs){
		if (&dir==&delDir){
			break;
		}
		++it;
	}
	
	if (it!=currentDir->dirs.end()){
		DeleteRecursive(*it);
		currentDir->dirs.erase(it);
	}
	
	WriteDirectoryAndHeader();
}

void Vault::MoveDir(Directory& dir){
	Directory* d = currentDir;
	while (d){
		if (d==&dir){
			return;
		}
		d = d->parent;
	}
	
	Directory* oldParent = dir.parent;
	currentDir->LinkDir(dir);
	oldParent->UnlinkDir(dir);
	WriteDirectoryAndHeader();
}

void Vault::MoveFile(FileDescriptor& desc){
	Directory* oldParent = desc.parent;
	currentDir->LinkFile(desc);
	oldParent->UnlinkFile(desc);
	WriteDirectoryAndHeader();
}

void Vault::SetKey(Sha3State& k){
	key = k;
	encryptKey = GenerateKey(key,ENCRYPT_KEY_CONSTANT);
}

void Vault::SetFile(std::fstream&& f,const std::string& path){
	vaultPath = path;
	vaultFile = std::move(f);
}

bool Vault::TryDecrypt(Sha3State& k){
	SetKey(k);
	
	Sha3State headerKey = GenerateKey(key,HEADER_KEY_CONSTANT);
	BufferDecryptCtx ctx{vaultFile,headerKey};
	
	vaultFile.seekg(VAULT_HEADER_OFFSET,std::ios::end);
	u8 zeroes[ZERO_VECTOR_SIZE];
	ctx.Decrypt(&zeroes[0],ZERO_VECTOR_SIZE);
	
	for (u32 i=0;i<ZERO_VECTOR_SIZE;++i){
		if (zeroes[i]!=0){
			if (gDebug){
				std::cout << "Decrypt prefix: " << i*8+std::countr_zero(zeroes[i]) << std::endl;
			}
			return false;
		}
	}
	
	if (gDebug){
		std::cout << "Decrypt prefix: " << ZERO_VECTOR_SIZE*8 << std::endl;
	}
	
	u64 locDirSize;
	ctx.DecryptU64(locDirSize);
	fileBlockEnd = (u64)vaultFile.tellg()-(PLAIN_HEADER_SIZE+VAULT_HEADER_SIZE+locDirSize);
	
	return true;
}

bool Vault::OpenFromFile(){
	Sha3State locDirKey = GenerateKey(key,LOCDIR_KEY_CONSTANT);
	BufferDecryptCtx ctx{vaultFile,locDirKey};
	
	vaultFile.seekg(fileBlockEnd);
	if (!vaultFile)
		return false;
	
	ctx.DecryptLocationDirectory(directory);
	if (!vaultFile)
		return false;
	
	currentDir = &directory.root;
	return true;
}

bool Vault::WriteFileAtEnd(const File& file,const FileDescriptor& desc){
	Sha3State encryptCopy = encryptKey;
	encryptCopy.UpdateU64(desc.genTime);
	
	BufferEncryptCtx ctx{vaultFile,encryptCopy};
	vaultFile.seekp(fileBlockEnd);
	
	encryptCopy.UpdateU32(desc.salt);
	
	ctx.Encrypt(FILE_MAGIC,sizeof(FILE_MAGIC));
	
	ctx.Encrypt(file.data.data(),file.data.size());
	return true;
}

bool Vault::WriteDirectoryAndHeader(){
	Sha3State locDirKey = GenerateKey(key,LOCDIR_KEY_CONSTANT);
	BufferEncryptCtx ctx{vaultFile,locDirKey};
	
	vaultFile.seekp(fileBlockEnd);
	ctx.EncryptLocationDirectory(directory);
	u64 locDirSize = (u64)vaultFile.tellg()-fileBlockEnd;
	
	BufferWriteCtx plainCtx{vaultFile};
	plainCtx.WritePlainHeader(salt);
	
	Sha3State headerKey = GenerateKey(key,HEADER_KEY_CONSTANT);
	
	BufferEncryptCtx headerCtx{vaultFile,headerKey};
	headerCtx.EncryptVaultHeader(locDirSize);
	
	PostWrite(locDirSize);
	return vaultFile.good();
}

void Vault::PostWrite(u64 locDirSize){
	u64 fileSize = fileBlockEnd+locDirSize+PLAIN_HEADER_SIZE+VAULT_HEADER_SIZE;
	fs::resize_file(vaultPath,fileSize);
}

bool Vault::AtRoot() const {
	return currentDir==&directory.root;
}

SecretString Vault::GetPath() const {
	Directory* currCopy = currentDir;
	SecretString name{};
	while (currCopy){
		name.insert(0,1,'/');
		name.insert(name.begin(),currCopy->name.begin(),currCopy->name.end());
		currCopy = currCopy->parent;
	}
	return name;
}

void PrintHash(HashResult res){
	for (u64 i=0;i<HASH_BYTES;i++){
		std::cout << std::hex << (int)res[i];
	}
	std::cout << std::dec;
}

void DisplayKeyColors(Sha3State key){
	Sha3State colorKey = GenerateKey(key,COLOR_KEY_CONSTANT);
	
	for (u32 i=0;i<4;++i){
		SetBackgroundRGB(colorKey.result[i*3]&0xF8,colorKey.result[i*3+1]&0xF8,colorKey.result[i*3+2]&0xF8);
		std::cout << "  ";
	}
	
	ResetTextStyle();
}

bool LoadVault(Vault& v,const std::string& path){
	std::error_code ec;
	if (!fs::exists(path,ec)){
		std::cout << "Could not find path '" << path << "'!" << std::endl;
		return false;
	}
	
	std::fstream vaultFile{path,std::ios::in|std::ios::out|std::ios::binary};
	
	BufferReadCtx readCtx{vaultFile};
	readCtx.SeekToHeaderPos();
	PlainHeader plainHeader;
	readCtx.ReadPlainHeader(plainHeader);
	
	if (memcmp(&plainHeader.magic[0],VAULT_MAGIC,sizeof(VAULT_MAGIC))!=0){
		std::cout << "This is not a vault file!" << std::endl;
		std::cout << "Found " << std::hex << *((u32*)&plainHeader.magic[0]) << std::endl;
		std::cout << "Expected " << *((u32*)&VAULT_MAGIC[0]) << std::endl;
		std::cout << std::dec;
		return false;
	}
	
	if (plainHeader.version>VERSION_NUMBER){
		std::cout << "Vault file uses a newer version of Vault!" << std::endl;
		return false;
	}
	
	v.salt = plainHeader.salt;
	
	v.SetFile(std::move(vaultFile),path);
	
	bool decrypted = false;
	Sha3State key;
	while (!decrypted){
		SecretString pass;
		std::cout << "Enter master key: ";
		std::cout << std::flush;
		PasswordEntry(pass);
		std::cout << std::endl;
		if (pass.empty())
			return false;
		
		key = InitKey(pass,plainHeader.salt);
		
		decrypted = v.TryDecrypt(key);
		if (!decrypted){
			std::cout << "Wrong password!" << std::endl;
		}
	}
	
	if (!v.OpenFromFile()){
		std::cout << "Error while reading location directory!" << std::endl;
	}
	
	return true;
}

bool CreateVault(Vault& v){
	std::string path;
	
	std::cout << "Creating new vault..." << '\n';
	
	while (true){
		std::cout << "Enter filename for vault: ";
		std::cout << std::flush;
		std::getline(std::cin,path);
		std::error_code err;
		
		if (path.empty()) return false;
		
		if (fs::exists(path,err)){
			std::cout << "Filename '" << path << "' already exists!" << std::endl;
			std::cout << "Delete? Y/N " << std::flush;
			YesNoAnswer yn = GetYesNoAnswer();
			std::cout << '\n';
			if (yn!=YesNoAnswer::Yes)
				continue;
			
			if (!fs::remove(path,err)){
				std::cout << "Could not delete!" << std::endl;
				return false;
			}
			break;
		} else {
			break;
		}
	}
	
	bool canWrite;
	{
		std::ofstream testWrite{path,std::ios::out|std::ios::binary};
		canWrite = testWrite.good();
	}
	
	if (!canWrite){
		std::cout << "Cannot write to '" << path << "'!" << std::endl;
		return false;
	}
	
	v.vaultFile = std::fstream{path,std::ios::in|std::ios::out|std::ios::binary};
	v.vaultPath = path;
	
	if (!GenerateSalt(v.salt)){
		std::cout << "Could not generate random salt!" << std::endl;
		return false;
	}
	
	SecretString masterPass{};
	
	
	while (true){
		SecretString checkPass{};
		
		std::cout << "Enter vault master key: " << std::flush;
		PasswordEntry(masterPass);
		std::cout << '\n';
		if (masterPass.empty()){
			std::cout << "Canceling..." << std::endl;
			std::error_code err;
			fs::remove(path,err);
			return false;
		}
		
		std::cout << "Confirm master key: " << std::flush;
		PasswordEntry(checkPass);
		std::cout << '\n';
		if (checkPass==masterPass){
			break;
		} else {
			std::cout << "Master keys do not match!" << std::endl;
		}
	}
	Sha3State key = InitKey(masterPass,v.salt);
	v.SetKey(key);
	v.fileBlockEnd = 0;
	v.directory = {};
	v.currentDir = &v.directory.root;
	
	if (!v.WriteDirectoryAndHeader()){
		std::cout << "Could not write vault to file!" << std::endl;
		return false;
	}
	
	return true;
}

void DisplayHelpMessage(){
	std::cout << "vault usage:\n";
	std::cout << "\tvault <vault_path>\n";
	std::cout << std::flush;
}

const char* IllegalCharSet = "/\\?\"':<>|$";

bool LegalName(const SecretString& name){
	if (name.size()>127) return false;
	
	const char* it = &IllegalCharSet[0];
	while (*it!=0){
		if (name.find(*it)!=std::string::npos)
			return false;
		++it;
	}
	
	return true;
}

void PrintSize(u64 size){
	std::stringstream ss{};
	ss << std::setfill('0');
	
	if (size<1024){
		ss << size << " B";
	} else if (size<1024*1024){
		ss << size/1024 << '.' << std::setw(2) << ((size%1024)*100)/1024 << " KB";
	} else if (size<1024*1024*1024){
		ss << size/(1024*1024) << '.' << std::setw(2) << ((size%(1024*1024))*100)/(1024*1024) << " MB";
	} else {
		ss << size/(1024*1024*1024) << '.' << std::setw(2) << ((size%(1024*1024*1024))*100)/(1024*1024*1024) << " GB";
	}
	
	std::cout << ss.str();
}

std::string FileMenu(Vault& v,FileDescriptor* file){
	FilePointer fp = v.GetFile(*file);
	if (fp==nullptr){
		return "File corrupted!";
	}
	
	u8 key;
	bool show = false;
	bool hasCopied = false;
	std::string msg = {};
	Secret secret{};
	if (file->type==FileType::Secret){
		fp->readHead = 0;
		u32 length = fp->ReadU32();
		secret = {SecretType::Service,file->genTime,{length}};
	}
	
	while (true){
		ClearConsole();
		
		std::cout << "File Menu\n";
		std::cout << file->name << '\n';
		PrintSize(file->location.size+FILE_HEADER_SIZE);
		if (gDebug){
			std::cout << " (" << file->location.size+FILE_HEADER_SIZE << ")";
		}
		
		std::cout << '\n';
		if (gDebug){
			std::cout << "Offset: " << file->location.offset << '\n';
		}
		PrintDateAndTime(file->genTime);
		std::cout << '\n';
		std::cout << '\n';
		
		if (show){
			if (file->type==FileType::File){
				u64 lines = 0;
				u64 cols = 0;
				for (const u8& c : fp->data){
					std::cout << c;
					++cols;
					if (c=='\n'||cols>80){
						cols = 0;
						++lines;
					}
					if (lines>20){
						std::cout << "...";
						break;
					}
				}
			} else if (file->type==FileType::Secret){
				SecretString pass = secret.GetPass(v.key);
				std::cout << pass;
			}
		}
		std::cout << "\n\n\n";
		
		if (!show)
			std::cout << "s: Show\n";
		else
			std::cout << "s: Hide\n";
		
		std::cout << "e: Export file\n";
		if (!hasCopied)
			std::cout << "c: Copy to clipboard\n";
		else
			std::cout << "c: Clear clipboard\n";
		std::cout << "q: Back\n";
		
		std::cout << '\n' << msg << '\n';
		std::cout << std::endl;
		
		key = GetKey();
		
		if (key=='q'||key==3||key==27||key==' '||key=='\n'){
			break;
		} else if (key=='s'){
			show = !show;
		} else if (key=='e'){
			std::cout << "Are you sure you wish to export? Y/N " << std::flush;
			auto answer = GetYesNoAnswer();
			if (answer!=YesNoAnswer::Yes) continue;
			std::cout << std::endl;
			
			std::string path = {};
			std::cout << "Enter path to export to (default " << file->name << "): " << std::flush;
			std::getline(std::cin,path);
			std::error_code ec;
			
			TruncateString(path);
			if (path.empty()){
				path = file->name;
			}
			
			if (fs::exists(path,ec)){
				std::cout << "Path already exists! Overwrite? Y/N " << std::flush;
				auto answer = GetYesNoAnswer();
				if (answer!=YesNoAnswer::Yes){
					continue;
				}
			}
			
			std::ofstream outFile{path,std::ios::out|std::ios::binary|std::ios::trunc};
			if (!outFile){
				msg = "Could not write to path!";
				continue;
			}
			
			if (file->type==FileType::Secret){
				SecretString pass = secret.GetPass(v.key);
				outFile.write(pass.data(),pass.size());
			} else {
				outFile.write((char*)fp->data.data(),fp->data.size());
			}
			
			msg = "File exported to '"+path +"'.";
		} else if (key=='c'){
			if (!hasCopied){
				if (fp->data.size()>2048){
					std::cout << "This file is large. Are you sure you want to copy? Y/N " << std::flush;
					auto answer = GetYesNoAnswer();
					if (answer!=YesNoAnswer::Yes) continue;
				}
				
				if (file->type==FileType::Secret){
					SecretString pass = secret.GetPass(v.key);
					SetClipboard(pass);
				} else {
					SecretString str{};
					for (const auto& c : fp->data){
						str.push_back(c);
					}
					SetClipboard(str);
				}
				
				msg = "Copied to clipboard.";
			} else {
				ClearClipboard();
				msg = "Clipboard cleared.";
			}
			
			hasCopied = !hasCopied;
		}
	}
	
	return {};
}

std::string DirectoryCreateMenu(Vault& v){
	SecretString name;
	
	std::cout << "Enter directory name: " << std::flush;
	std::getline(std::cin,name);
	std::cout << std::endl;
	
	TruncateString(name);
	if (!LegalName(name)) return "Illegal characters in name '"+name+"'!";
	if (name.empty()) return {};
	
	if (v.currentDir->NameIsTaken(name)){
		return "'"+name+"' is already taken!";
	}
	
	v.CreateDir(name);
	return "Created directory '"+name+"/' successfully.";
}

std::string FileCreateMenu(Vault& v){
	ClearConsole();
	
	std::cout << "Select file type.\n\n";
	std::cout << "s: Randomly generated secret\n";
	std::cout << "f: Import file from disk\n";
	std::cout << "c: Enter a short string\n";
	std::cout << "q: Cancel\n";
	std::cout << std::endl;
	
	File file = {};
	u8 choice;
	bool chosen = false;
	while (!chosen){
		choice = GetKey();
		switch (choice){
			case 's':
			case 'f':
			case 'c':
				chosen = true;
				break;
			case 'q':
			case 3:
			case 27:
				return {};
		}
	}
	
	SecretString name;
	std::string path;
	
	if (choice=='s'){
		std::cout << "Enter name of secret to create: " << std::flush;
	} else if (choice=='c'){
		std::cout << "Enter name of file to create: " << std::flush;
	} else if (choice=='f'){
		std::cout << "Enter path of file to import: " << std::flush;
	}
	std::getline(std::cin,name);
	TruncateString(name);
	
	if (choice=='f'){
		std::error_code ec;
		path = name;
		auto filename = fs::path(path).filename();
		name = (SecretString)filename.string();
	}
	
	if (!LegalName(name)) return "Illegal characters in name '"+name+"'!";
	if (name.empty()) return {};
	
	if (v.currentDir->NameIsTaken(name)){
		return "Name '"+name+"' is already taken!";
	}
	
	FileDescriptor fileDesc = {};
	fileDesc.name = name;
	
	if (choice=='s'){
		fileDesc.type = FileType::Secret;
		u32 size = 0;
		while (size==0){
			std::cout << "Enter secret length (default 24): ";
			if (!ReadStdInNumber(size)){
				size = 0;
				std::cout << "Could not parse number!" << std::endl;
			} else if (size>=10000){
				size = 0;
				std::cout << "Secret length too big!" << std::endl;
			} else if (size==0){
				// set to default if no number is entered
				size = 24;
			}
		}
		
		file.data = {};
		file.WriteU32(size);
		v.AddFile(file,fileDesc);
	} else if (choice=='f'){
		fileDesc.type = FileType::File;
		if (path.empty()) return {};
		
		std::error_code ec;
		if (!fs::exists(path,ec)){
			return "Path doesn't exist!";
		}
		
		{
			std::fstream importFile{path,std::ios::in|std::ios::binary};
			if (!importFile){
				return "Cannot read file!";
			}
			std::error_code err;
			size_t size = fs::file_size(path,err);
			file.data.resize(size);
			importFile.read((char*)file.data.data(),size);
		}
		
		v.AddFile(file,fileDesc);
	} else if (choice=='c'){
		fileDesc.type = FileType::File;
		SecretString str = {};
		std::cout << "Enter string: " << std::flush;
		std::getline(std::cin,str);
		std::cout << std::endl;
		
		file.data.reserve(str.size());
		for (const auto& c : str){
			file.data.push_back(c);
		}
		
		v.AddFile(file,fileDesc);
	} else {
		return {};
	}
	
	
	return "Created file '"+name+"' successfully.";
}

std::string DirectoryDeleteMenu(Vault& v,Directory& delDir){
	std::cout << "Delete directory '" << delDir.name << "' recursively? Y/N " << std::flush;
	auto answer = GetYesNoAnswer();
	if (answer!=YesNoAnswer::Yes) return {};
	
	SecretString nameCopy = delDir.name;
	v.DeleteDir(delDir);
	return "Directory '"+nameCopy+"' deleted successfully";
}

std::string FileDeleteMenu(Vault& v,FileDescriptor& delFile){
	std::cout << "Delete file '" << delFile.name << "'? Y/N " << std::flush;
	auto answer = GetYesNoAnswer();
	if (answer!=YesNoAnswer::Yes) return {};
	
	SecretString nameCopy = delFile.name;
	v.DeleteFile(delFile);
	return "File '"+nameCopy+"' deleted successfully";
}

Directory* GetDirFromList(Directory* currDir,size_t select){
	if (select==0) return currDir->parent;
	if (select>=currDir->dirs.size()+1) return nullptr;
	
	select -= 1;
	u64 c = 0;
	for (auto& dir : currDir->dirs){
		if (c==select){
			return &dir;
		}
		++c;
	}
	return nullptr;
}

FileDescriptor* GetFileFromList(Directory* currDir,size_t select){
	if (select<currDir->dirs.size()+1) return nullptr;
	
	select -= currDir->dirs.size()+1;
	if (select>=currDir->files.size()) return nullptr;
	
	u64 c = 0;
	for (auto& file : currDir->files){
		if (c==select){
			return &file;
		}
		++c;
	}
	return nullptr;
}

void VaultMenu(Vault& v){
	u8 c;
	std::string msg = {};
	
	size_t selectIndex = 1;
	size_t itemCount;
	auto*& currDir = v.currentDir;
	Directory* delDir = nullptr;
	FileDescriptor* selectFile = nullptr;
	
	bool moving = false;
	Directory* moveDir = nullptr;
	FileDescriptor* moveFile = nullptr;
	
	while (true){
		ClearConsole();
		std::cout << "Vault Menu\n";
		DisplayKeyColors(v.key);
		std::cout << "\n\n";
		
		itemCount = 0;
		
		DirTextStyle();
		if (itemCount==selectIndex)
			InvertTextStyle();
		
		if (!v.AtRoot()){
			std::cout << "..\n";
		} else {
			std::cout << "\n";
		}
		ResetTextStyle();
		++itemCount;
		std::cout << std::setfill(' ');
		size_t justSize;
		size_t biggestName = std::max(currDir->GetBiggestNameSize()+12,24ULL);
		for (const auto& subdir : currDir->dirs){
			DirTextStyle();
			if (itemCount==selectIndex)
				InvertTextStyle();
			justSize = biggestName-(subdir.name.size()+1);
			if (subdir.recursiveSize>=1024) ++justSize;
			std::cout << subdir.name << '/' << std::setw(justSize);
			PrintSize(subdir.recursiveSize);
			std::cout << '\n';
			ResetTextStyle();
			++itemCount;
		}
		
		for (const auto& file : currDir->files){
			if (file.type==FileType::Secret)
				SecretTextStyle();
			if (itemCount==selectIndex)
				InvertTextStyle();
			justSize = biggestName-file.name.size();
			if (file.location.size+FILE_HEADER_SIZE>=1024) ++justSize;
			std::cout << file.name << std::setw(justSize);
			if (file.type!=FileType::Secret)
				PrintSize(file.location.size+FILE_HEADER_SIZE);
			else {
				// read the length of the password instead of its size in bytes
				std::stringstream ss{};
				auto fp = v.GetFile(file);
				if (!fp){
					ss << "? L";
				} else {
					u32 size = fp->ReadU32();
					ss << size << " L";
				}
				std::cout << ss.str();
			}
				
			std::cout << '\n';
			ResetTextStyle();
			++itemCount;
		}
		
		selectFile = GetFileFromList(currDir,selectIndex);
		
		std::cout << '\n';
		std::cout << v.GetPath() << "\n\n";
		
		if (moving){
			std::cout << "m: Move here\n";
			std::cout << "q: Cancel\n";
		} else {
			std::cout << "d: New directory\n";
			std::cout << "f: New file\n";
			delDir = nullptr;
			if (selectIndex!=0){
				delDir = GetDirFromList(currDir,selectIndex);
				
				if (delDir!=nullptr){
					std::cout << "r: Remove directory\n";
					std::cout << "n: Rename directory\n";
					std::cout << "m: Move directory\n";
				} else if (selectFile!=nullptr){
					std::cout << "r: Remove file\n";
					std::cout << "n: Rename file\n";
					std::cout << "m: Move file\n";
				}
			}
			std::cout << "q: Quit\n";
		}
		
		if (!msg.empty()){
			std::cout << '\n' << msg << '\n';
			msg.clear();
		}
		std::cout << std::endl;
		
		c = GetKey();
		
		if (c=='q'||c==3){
			break;
		} else if (c==27&&!v.AtRoot()){
			currDir = currDir->parent;
		} else if (c=='j'){
			++selectIndex;
			selectIndex %= itemCount;
		} else if (c=='k'){
			if (v.AtRoot()&&selectIndex==1){
				selectIndex = itemCount-1;
			} else {
				--selectIndex;
				selectIndex += itemCount;
				selectIndex %= itemCount;
			}
		} else if (c=='u'){
			selectIndex = itemCount-1;
		} else if (c=='i'){
			selectIndex = 0;
		} else if (c=='d'){
			msg = DirectoryCreateMenu(v);
		} else if (c=='f'){
			msg = FileCreateMenu(v);
		} else if (c=='r'){
			if (delDir!=nullptr){
				msg = DirectoryDeleteMenu(v,*delDir);
				itemCount -= 1;
				selectIndex %= itemCount;
			} else if (selectFile!=nullptr){
				msg = FileDeleteMenu(v,*selectFile);
				itemCount -= 1;
				selectIndex %= itemCount;
			}
		} else if (c==' '||c=='\n'||c=='\r'){
			if (selectIndex<currDir->dirs.size()+1){
				Directory* newDir = GetDirFromList(currDir,selectIndex);
				if (newDir!=nullptr){
					currDir = newDir;
					selectIndex = 0;
				}
			} else {
				// opened a file
				msg = FileMenu(v,selectFile);
			}
		} else if (c=='n'){
			if (delDir==nullptr&&selectFile==nullptr) 
				continue;
			
			SecretString name{};
			std::cout << "Enter new name: " << std::flush;
			std::getline(std::cin,name);
			
			TruncateString(name);
			if (!LegalName(name)){
				msg = "Illegal characters in name '"+name+"'!";
				continue;
			}
			
			if (name.empty()) continue;
			
			if (delDir!=nullptr){
				delDir->name = name;
			} else {
				selectFile->name = name;
			}
			
			v.WriteDirectoryAndHeader();
		} else if (c=='m'){
			if (!moving){
				if (delDir==nullptr&&selectFile==nullptr)
					continue;
				
				moving = true;
				if (delDir!=nullptr)
					moveDir = delDir;
				else
					moveFile = selectFile;
			} else {
				moving = false;
				if (moveDir!=nullptr){
					v.MoveDir(*moveDir);
					moveDir = nullptr;
				} else {
					v.MoveFile(*moveFile);
					moveFile = nullptr;
				}
			}
		} else if (c=='D'){
			if (!gDebug)
				msg = "Debug mode enabled.";
			else
				msg = "Debug mode disabled.";
			
			gDebug = !gDebug;
		}
		
		if (v.AtRoot()&&selectIndex==0)
			selectIndex = 1;
	}
	
	ClearConsole();
	std::cout << "Quitting..." << std::endl;
}
