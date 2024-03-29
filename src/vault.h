#pragma once

#include "types.h"

#include <string>
#include <cstring>
#include <map>
#include <array>
#include <memory>
#include <vector>
#include <list>
#include <fstream>

#include "sha3/sha3.h"

#define HASH_BITS 512
#define HASH_BYTES (HASH_BITS>>3)

#define SUB_HASH_ROUNDS        8
#define COLOR_HASH_ROUNDS   8192
#define SECRET_HASH_ROUNDS 16384

#define ZERO_VECTOR_SIZE 64
#define FILE_ZERO_VECTOR_SIZE 8
#define VERSION_NUMBER 0
#define VAULT_VERSION_STRING "0.1.0"
#define EXT_ENCRYPT_EXTENSION "venc"
#define EXT_DECRYPT_EXTENSION "vdec"

#define BALLOON_SPACE_COST    2048
#define BALLOON_TIME_COST        2
#define BALLOON_DELTA_COST       8
#define BALLOON_EXTRACT_COST 16384

constexpr u8 VAULT_MAGIC[] = {'E','V','\x00','\x01'};
constexpr u8 FILE_MAGIC[] = {'E','F','\x05','\x04'};
constexpr u8 EXT_FILE_MAGIC[] = {'E','E','\x07','\x08'};

typedef std::array<u8,HASH_BYTES> HashResult;
typedef std::array<u8,24> SecretSalt;
const std::string passwordChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789!?-_@%";

struct Sha3State {
	sha3_context ctx;
	HashResult result;
	const void* hashPointer = NULL;
	
	inline void Clear(){
		volatile u8* overwrite = (volatile u8*)this;
		for (size_t i=0;i<sizeof(Sha3State);++i){
			overwrite[i] = 0;
		}
	}
	
	inline Sha3State(){
		sha3_Init(&ctx,HASH_BITS);
	}
	
	inline ~Sha3State(){
		Clear();
	}
	
	inline Sha3State(Sha3State&& s){
		ctx = s.ctx;
		result = s.result;
		hashPointer = s.hashPointer;
		s.Clear();
	}
	
	inline Sha3State& operator=(Sha3State&& s){
		ctx = s.ctx;
		result = s.result;
		hashPointer = s.hashPointer;
		s.Clear();
		
		return *this;
	}
	
	inline Sha3State(const Sha3State& s){
		ctx = s.ctx;
		result = s.result;
		hashPointer = s.hashPointer;
	}
	
	inline Sha3State& operator=(const Sha3State& s){
		ctx = s.ctx;
		result = s.result;
		hashPointer = s.hashPointer;
		
		return *this;
	}
	
	inline void Reset(){
		sha3_Init(&ctx,HASH_BITS);
	}
	
	inline void UpdateString(const std::string& str){
		sha3_Update(&ctx,str.data(),str.size());
		Rehash(1);
	}
	
	inline void RawUpdateU64(u64 u){
		sha3_Update(&ctx,&u,sizeof(u64));
	}
	
	inline void UpdateU64(u64 u){
		RawUpdateU64(u);
		Rehash(1);
	}
	
	inline void RawUpdateU32(u32 u){
		sha3_Update(&ctx,&u,sizeof(u32));
	}
	
	inline void UpdateU32(u32 u){
		RawUpdateU32(u);
		Rehash(1);
	}
	
	inline void UpdateU16(u16 u){
		sha3_Update(&ctx,&u,sizeof(u16));
		Rehash(1);
	}
	
	inline void RawUpdateResult(const HashResult& res){
		sha3_Update(&ctx,&res[0],sizeof(HashResult));
	}
	
	inline void UpdateResult(const HashResult& res){
		RawUpdateResult(res);
		Rehash(1);
	}
	
	inline void UpdateSecretSalt(const SecretSalt& salt){
		sha3_Update(&ctx,&salt[0],sizeof(SecretSalt));
		Rehash(1);
	}
	
	inline void Rehash(size_t count){
		for (u64 i=0;i<count;++i){
			hashPointer = sha3_Finalize(&ctx);
		}
		memcpy(&result[0],hashPointer,HASH_BYTES);
	}
};

struct Secret {
	SecretString username;
	SecretSalt secretSalt;
	u64 genTime;
	u16 length;
	
	SecretString GetPass();
	Secret(const Secret&) = delete;
	Secret(Secret&&) = delete;
	
	inline Secret() : username(),secretSalt(),genTime(),length() {}
	inline ~Secret(){
		volatile u8* overwrite = (volatile u8*)this;
		for (size_t i=0;i<sizeof(Secret);++i){
			overwrite[i] = 0;
		}
	}
};

enum class FileType : u16 {
	File = 0,
	Secret
};

struct File {
	std::vector<u8> data;
	u64 readHead;
	
	File() : data() {}
	~File(){
		std::fill(data.begin(),data.end(),0);
	}
	
	void WriteU64(u64);
	u64 ReadU64();
	void WriteU32(u32);
	u32 ReadU32();
	void WriteU16(u16);
	u16 ReadU16();
	void WriteU8(u8);
	u8 ReadU8();
	
	void WriteShortString(const SecretString&);
	void ReadShortString(SecretString&);
	
	void WriteSecret(const Secret&);
	void ReadSecret(Secret&);
	
	File(const File&) = delete;
	File(File&&) = delete;
};

struct FileLocation {
	u64 offset;
	u64 size;
};

struct Directory;

struct FileDescriptor {
	SecretString name;
	u32 salt;
	FileType type;
	u64 genTime;
	FileLocation location;
	
	Directory* parent = nullptr;
};

struct Directory {
	SecretString name = {};
	std::list<Directory> dirs = {};
	std::list<FileDescriptor> files = {};
	
	Directory* parent = nullptr;
	size_t recursiveSize = 0;
	
	void AddFile(FileDescriptor desc);
	void DeleteFile(FileDescriptor& delFile);
	void CreateDir(const SecretString&);
	void DeleteDir(Directory& delDir);
	u64 CountFiles() const;
	bool NameIsTaken(const SecretString&) const;
	
	void AddSize(s64);
	u64 GetBiggestNameSize() const;
	void UnlinkDir(Directory&);
	void LinkDir(Directory&);
	void UnlinkFile(FileDescriptor&);
	void LinkFile(FileDescriptor&);
	void ShrinkFilesAfter(u64,u64);
	void FixPointers();
};

struct LocationDirectory {
	Directory root = {};
};

typedef std::unique_ptr<File> FilePointer;

// magic + version + salt
constexpr u64 PLAIN_HEADER_SIZE = sizeof(FILE_MAGIC)+sizeof(u32)+sizeof(u64);
// zeros + locdir size + last edit time size
constexpr u64 VAULT_HEADER_SIZE = ZERO_VECTOR_SIZE+sizeof(u64)*3;
constexpr u64 FILE_HEADER_SIZE = sizeof(FILE_MAGIC);
constexpr u64 EXT_FILE_HEADER_SIZE = sizeof(EXT_FILE_MAGIC)+sizeof(u64)+FILE_ZERO_VECTOR_SIZE;

constexpr s64 PLAIN_HEADER_OFFSET = -PLAIN_HEADER_SIZE-VAULT_HEADER_SIZE;
constexpr s64 VAULT_HEADER_OFFSET = -VAULT_HEADER_SIZE;
constexpr u64 MIN_LOC_DIR_SIZE = sizeof(u64)*2;
constexpr u64 MIN_FILE_SIZE = MIN_LOC_DIR_SIZE+VAULT_HEADER_SIZE+PLAIN_HEADER_SIZE;

struct PlainHeader {
	u8 magic[sizeof(FILE_MAGIC)];
	u32 version;
	u64 salt;
};
static_assert(sizeof(PlainHeader)==PLAIN_HEADER_SIZE);

struct VaultHeader {
	u8 zeroes[ZERO_VECTOR_SIZE];
	u64 locDirSize;
	u64 fileBlockEnd;
	u64 lastEditTime;
};
static_assert(sizeof(VaultHeader)==VAULT_HEADER_SIZE);

struct Vault {
	Sha3State key;
	Sha3State encryptKey;
	std::string vaultPath;
	std::fstream vaultFile;
	u64 salt;
	
	u64 fileBlockEnd = 0;
	u64 editTime = 0;
	LocationDirectory directory;
	Directory* currentDir;
	
	void SetKey(Sha3State& k);
	void SetFile(std::fstream&&,const std::string& path);
	
	FilePointer GetFile(const FileDescriptor&);
	void AddFile(const File& file,FileDescriptor& header);
	void DeleteFileRaw(FileDescriptor& header);
	void DeleteFile(FileDescriptor& header);
	
	void CreateDir(const SecretString& name);
	void DeleteDir(Directory& delDir);
	void DeleteRecursive(Directory& delDir);
	
	void MoveDir(Directory& dir);
	void MoveFile(FileDescriptor& file);
	
	// called when testing out password
	bool TryDecrypt(Sha3State& k);
	
	// called after TryDecrypt
	bool OpenFromFile();
	
	bool WriteFileAtEnd(const File& file,const FileDescriptor& desc);
	bool WriteDirectoryAndHeader();
	void PostWrite(u64 locDirSize,u64 padSize);
	
	bool AtRoot() const;
	SecretString GetPath() const;
};


void DisplayHelpMessage();
bool CreateVault(Vault& v);
bool LoadVault(Vault& v,const std::string& path);
void VaultMenu(Vault& v);
