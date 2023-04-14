#pragma once

#include "types.h"

#include <string>
#include <cstring>
#include <map>
#include <array>

#include "sha3/sha3.h"

#define HASH_BITS 512
#define HASH_BYTES (HASH_BITS>>3)

#define MASTER_HASH_ROUNDS 200000
#define SUB_HASH_ROUNDS 8
#define MINOR_HASH_ROUNDS 256

// SHA-2 init hash constants
#define ENCRYPT_KEY_CONSTANT 0xbb67ae856a09e667ULL
#define COLOR_KEY_CONSTANT 0xa54ff53a3c6ef372ULL

#define ZERO_VECTOR_SIZE 64
#define VERSION_NUMBER 1


class SecretString : public std::string {
public:
	~SecretString(){
		memset(this->data(),0,this->size());
	}
};

typedef std::array<u8,HASH_BYTES> HashResult;
const std::string passwordChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789!?-_@%";

struct PassOptions {
	u32 length = 24;
	
	inline size_t GetEntropy() const {
		return length*6;
	}
};


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
	
	inline void UpdateString(const std::string& str){
		sha3_Update(&ctx,str.data(),str.size());
		Rehash(1);
	}
	
	inline void UpdateU64(u64 u){
		sha3_Update(&ctx,&u,sizeof(u64));
		Rehash(1);
	}
	
	inline void UpdatePassOptions(const PassOptions& ops){
		static_assert(sizeof(ops)==sizeof(u32));
		sha3_Update(&ctx,&ops.length,sizeof(ops.length));
		Rehash(1);
	}
	
	inline void Rehash(size_t count){
		for (u64 i=0;i<count;++i){
			hashPointer = sha3_Finalize(&ctx);
		}
		memcpy(&result[0],hashPointer,HASH_BYTES);
	}
};

enum class SecretType : u32 {
	Service = 0
};

struct Secret {
	SecretType type;
	u64 genTime;
	std::string name;
	PassOptions options = {};
	Sha3State key;
	
	void Open(Sha3State idKey);
	SecretString GetPass();
};

struct Identity {
	std::string name;
	u64 genTime;
	Sha3State key;
	std::map<std::string,Secret> secrets;
	
	inline bool SecretExists(const std::string& name){
		return secrets.contains(name);
	}
	
	void Open(Sha3State masterKey);
	std::string GetSecretNameFromIndex(size_t index);
	size_t GetSecretNameJust() const;
	void AddSecret(Secret& s);
	void DeleteSecret(const std::string& name);
};

struct Vault {
	Sha3State key;
	std::map<std::string,Identity> identities;
	std::string path;
	u64 salt;
	
	bool changed = false;
	
	bool Encrypt(std::ofstream& out,Sha3State key);
	bool Decrypt(std::ifstream& in,Sha3State key,bool& decrypted);
	void AddIdentity(Identity& id);
	void DeleteIdentity(const std::string& name);
	bool IdentityExists(const std::string& name) const;
	std::string GetIdentityNameFromIndex(size_t index) const;
};


void DisplayHelpMessage();
bool CreateVault(Vault& v);
bool LoadVault(Vault& v);
void VaultMenu(Vault& v);
