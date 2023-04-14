#include "vault.h"

#include <stddef.h>

#include "sha3/sha3.h"
#include "plat.h"

#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

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

void Secret::Open(Sha3State idKey){
	key = idKey;
	key.UpdateString(name);
	key.UpdateU64((u64)type);
	key.UpdateU64(genTime);
	key.UpdatePassOptions(options);
	key.Rehash(SUB_HASH_ROUNDS);
}

SecretString Secret::GetPass(){
	Sha3State keyClone = key;
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

void Identity::Open(Sha3State masterKey){
	key = masterKey;
	key.UpdateString(name);
	key.UpdateU64(genTime);
	key.Rehash(SUB_HASH_ROUNDS);
	
	for (auto& [name,secret] : secrets){
		secret.Open(key);
	}
}

std::string Identity::GetSecretNameFromIndex(size_t index){
	size_t i=0;
	for (const auto& [name,secret] : secrets){
		if (i==index) return name;
		++i;
	}
	return {};
}

size_t Identity::GetSecretNameJust() const {
	size_t maxL = 0;
	for (const auto& [name,s] : secrets){
		if (name.size()>maxL)
			maxL = name.size();
	}
	return maxL;
}

void Identity::AddSecret(Secret& s){
	s.Open(key);
	secrets[s.name] = s;
}

void Identity::DeleteSecret(const std::string& name){
	if (secrets.contains(name)){
		secrets.erase(name);
	}
}

struct BufferEncryptCtx {
	std::ofstream& out;
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
		Encrypt((u8*)&num,sizeof(u64));
	}
	
	void EncryptU32(u32 num){
		Encrypt((u8*)&num,sizeof(u32));
	}
	
	void EncryptString(const std::string& str){
		EncryptU64(str.size());
		Encrypt((const u8*)str.data(),str.size());
	}
	
	void EncryptSecret(const Secret& secret){
		EncryptU32((u32)secret.type);
		EncryptU64(secret.genTime);
		EncryptString(secret.name);
		
		static_assert(sizeof(PassOptions)==sizeof(u32));
		EncryptU32(secret.options.length);
	}
	
	void EncryptIdentity(const Identity& id){
		EncryptU64(id.genTime);
		size_t secretCount = id.secrets.size();
		EncryptU64(secretCount);
		for (const auto& [name,secret] : id.secrets){
			EncryptString(name);
			EncryptSecret(secret);
		}
	}
};

struct BufferDecryptCtx {
	std::ifstream& in;
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
		Decrypt((u8*)&num,sizeof(u64));
	}
	
	void DecryptU32(u32& num){
		Decrypt((u8*)&num,sizeof(u32));
	}
	
	void DecryptString(std::string& str){
		size_t size;
		DecryptU64(size);
		str.resize(size);
		u8* d = (u8*)str.data();
		Decrypt(d,size);
	}
	
	void DecryptSecret(Secret& secret){
		secret = {};
		u32 type;
		DecryptU32(type);
		secret.type = (SecretType)type;
		DecryptU64(secret.genTime);
		DecryptString(secret.name);
		
		static_assert(sizeof(PassOptions)==sizeof(u32));
		DecryptU32(secret.options.length);
	}
	
	void DecryptIdentity(Identity& id){
		id.secrets = {};
		DecryptU64(id.genTime);
		size_t secretCount;
		DecryptU64(secretCount);
		
		std::string name;
		Secret secret;
		for (size_t i=0;i<secretCount;++i){
			DecryptString(name);
			DecryptSecret(secret);
			id.secrets[name] = secret;
		}
	}
};

bool Vault::Encrypt(std::ofstream& out,Sha3State key){
	Sha3State encryptKey = GenerateKey(key,ENCRYPT_KEY_CONSTANT);
	BufferEncryptCtx ctx{out,encryptKey};
	
	u8 zeroes[ZERO_VECTOR_SIZE];
	memset(zeroes,0,ZERO_VECTOR_SIZE);
	
	ctx.Encrypt(&zeroes[0],ZERO_VECTOR_SIZE);
	u32 version = VERSION_NUMBER;
	ctx.EncryptU32(version);
	
	ctx.EncryptU64(identities.size());
	for (const auto& [name,id] : identities){
		ctx.EncryptString(name);
		ctx.EncryptIdentity(id);
	}
	
	changed = false;
	return ctx.out.good();
}

bool Vault::Decrypt(std::ifstream& in,Sha3State key,bool& decrypted){
	Sha3State decryptKey = GenerateKey(key,ENCRYPT_KEY_CONSTANT);
	BufferDecryptCtx ctx{in,decryptKey};
	
	u8 zeroes[ZERO_VECTOR_SIZE];
	ctx.Decrypt(&zeroes[0],ZERO_VECTOR_SIZE);
	for (u32 i=0;i<ZERO_VECTOR_SIZE;++i){
		if (zeroes[i]!=0){
			decrypted = false;
			return true;
		}
	}
	
	decrypted = true;
	
	u32 version;
	ctx.DecryptU32(version);
	if (version!=VERSION_NUMBER){
		return false;
	}
	
	identities = {};
	u64 count;
	ctx.DecryptU64(count);
	std::string name;
	Identity id;
	for (u64 i=0;i<count;++i){
		ctx.DecryptString(name);
		ctx.DecryptIdentity(id);
		id.name = name;
		identities[name] = id;
	}
	
	for (auto& [name,id] : identities){
		id.Open(key);
	}
	
	changed = false;
	return ctx.in.good();
}

void Vault::AddIdentity(Identity& id){
	id.Open(key);
	identities[id.name] = id;
	changed = true;
}

void Vault::DeleteIdentity(const std::string& name){
	if (identities.contains(name)){
		identities.erase(name);
		changed = true;
	}
}

bool Vault::IdentityExists(const std::string& name) const {
	return identities.contains(name);
}

std::string Vault::GetIdentityNameFromIndex(size_t index) const {
	size_t i = 0;
	for (const auto& [name,id] : identities){
		if (index==i) return name;
		++i;
	}
	return {};
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
	
	ResetBackground();
}

bool LoadVault(Vault& v){
	std::ifstream vaultFile{v.path,std::ios::in|std::ios::binary};
	if (!vaultFile){
		std::cout << "Could not read vault from '" << v.path << "'!" << std::endl;
		return false;
	}
	
	u64 salt;
	vaultFile.read((char*)&salt,sizeof(u64));
	v.salt = salt;
	
	auto pos = vaultFile.tellg();
	
	bool decrypted = false;
	Sha3State key;
	while (!decrypted){
		std::string pass;
		std::cout << "Enter master key: ";
		std::cout << std::flush;
		PasswordEntry(pass);
		std::cout << std::endl;
		if (pass.empty())
			return false;
		
		key = InitKey(pass,salt);
		
		vaultFile.seekg(pos);
		if (!v.Decrypt(vaultFile,key,decrypted)){
			std::cout << "Error while reading vault from '" << v.path << "'!" << std::endl;
			return false;
		}
		
		if (!decrypted){
			std::cout << "Wrong password!" << std::endl;
		}
	}
	
	v.key = key;
	DisplayKeyColors(key);
	std::cout << '\n';
	std::cout << "Vault successfully loaded..." << std::endl;
	
	return true;
}

bool SaveVault(Vault& v){
	std::string tempPath = v.path+".tmp";
	{
		std::ofstream vaultFile{tempPath,std::ios::out|std::ios::binary};
		if (!vaultFile){
			std::cout << "Could not save vault to '" << tempPath << "'!" << std::endl;
			return false;
		}
		
		vaultFile.write((const char*)&v.salt,sizeof(v.salt));
		
		if (!v.Encrypt(vaultFile,v.key)){
			std::cout << "Could not encrypt vault to '" << tempPath << "'!" << std::endl;
			return false;
		}
	}	
	
	std::error_code err;
	fs::remove(v.path,err);
	
	if (!fs::copy_file(tempPath,v.path,err)){
		std::cout << "Could not copy back temp file from '" << tempPath << "' to '" << v.path << "'!\n";
		std::cout << "Err: " << err.message() << std::endl;
		return false;
	}
	
	fs::remove(tempPath,err);
	
	std::cout << "Vault saved successfully." << std::endl;
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
		std::ofstream testRead{path,std::ios::out|std::ios::binary};
		canWrite = testRead.good();
	}
	
	if (path.empty()||!canWrite){
		std::cout << "Cannot write to '" << path << "'!" << std::endl;
		return false;
	}
	
	v.path = path;
	
	if (!GenerateSalt(v.salt)){
		std::cout << "Could not generate random salt!" << std::endl;
		return false;
	}
	v.identities = {};
	
	std::string masterPass{};
	
	std::cout << "Enter vault master key: " << std::flush;
	PasswordEntry(masterPass);
	std::cout << '\n';
	if (masterPass.empty()){
		std::cout << "Canceling..." << std::endl;
		std::error_code err;
		fs::remove(path,err);
		return false;
	}
	
	Sha3State key = InitKey(masterPass,v.salt);
	v.key = key;
	
	if (!SaveVault(v))
		return false;
	
	return true;
}

void DisplayHelpMessage(){
	std::cout << "vault usage:\n";
	std::cout << "\tvault <vault_path>\n";
	std::cout << std::flush;
}

std::string SecretCreateMenu(Vault& v,Identity& i){
	std::cout << "Enter secret name: ";
	std::string name;
	std::getline(std::cin,name);
	TruncateString(name);
	
	if (name.empty()) return {};
	
	if (i.SecretExists(name)){
		return "Secret '"+name+"' already exists!";
	}
	
	u32 l = 0;
	
	while (l==0){
		std::cout << "Enter secret length (default 24): ";
		if (!ReadStdInNumber(l)){
			l = 0;
			std::cout << "Could not parse number!" << std::endl;
		} else if (l>=10000){
			l = 0;
			std::cout << "Secret length too big!" << std::endl;
		} else if (l==0){
			// set to default if no number is entered
			l = 24;
		}
	}
	
	Secret s{};
	s.name = name;
	s.genTime = GetTime();
	s.options = {l};
	
	i.AddSecret(s);
	v.changed = true;
	
	return "Secret created successfully.";
}

std::string SecretMenu(Vault& v,Identity& id,Secret& secret){
	u8 c;
	std::string msg = {};
	bool show = false;
	bool copied = false;
	while (true){
		ClearConsole();
		std::cout << "Secret Menu\n";
		DisplayKeyColors(secret.key);
		std::cout << '\n';
		std::cout << "'" << secret.name << "'\n";
		PrintDate(secret.genTime);
		
		if (!show)
			std::cout << "\n\n\n\n";
		else
			std::cout << "\n\n" << secret.GetPass() << "\n\n";
		
		if (copied)
			std::cout << "c: Clear clipboard\n";
		else
			std::cout << "c: Copy to clipboard\n";
		
		if (!show)
			std::cout << "s: Show\n";
		else
			std::cout << "s: Hide\n";
		std::cout << "d: Delete secret\n";
		std::cout << "q: Back\n";
		
		if (!msg.empty())
			std::cout << '\n' << msg;
		msg = {};
		std::cout << std::endl;
		
		c = GetKey();
		
		if (c=='q'||c==3||c==27){
			break;
		} else if (c=='c'){
			if (copied){
				ClearClipboard();
				msg = "Clipboard cleared.";
			} else {
				SetClipboard(secret.GetPass());
				msg = "Copied to clipboard.";
			}
			copied = !copied;
		} else if (c=='s'){
			show = !show;
		} else if (c=='d'){
			std::cout << "Delete secret '"+secret.name+"'? Y/N " << std::flush;
			auto answer = GetYesNoAnswer();
			std::cout << std::endl;
			if (answer==YesNoAnswer::Yes){
				id.DeleteSecret(secret.name);
				v.changed = true;
				return "Secret '"+secret.name+"' deleted.\n";
			}
		}
	}
	
	return {};
}

std::string IdentityMenu(Vault& v,Identity& id){
	u8 c;
	std::string msg = {};
	while (true){
		ClearConsole();
		std::cout << "Identity Menu\n";
		DisplayKeyColors(id.key);
		std::cout << '\n';
		std::cout << "'" << id.name << "'\n";
		PrintDate(id.genTime);
		std::cout << "\n\n";
		
		if (!id.secrets.empty()){
			std::cout << "Secrets:\n";
			std::cout << std::setfill(' ');
			size_t nameJust = id.GetSecretNameJust()+6;
			size_t i=0;
			for (const auto& [name,s] : id.secrets){
				std::cout << (i+1)%10 << ": " << name << std::setw(nameJust-name.size()) << s.options.length << '\n';
				++i;
				if (i==10) break;
			}
		}
		
		std::cout << "\n";
		std::cout << "s: Add secret\n";
		std::cout << "d: Delete identity\n";
		std::cout << "q: Back\n";
		
		if (!msg.empty())
			std::cout << '\n' << msg << '\n';
		std::cout << std::endl;
		
		c = GetKey();
		
		if (c=='q'||c==3||c==27){
			break;
		} else if (c=='s'){
			msg = SecretCreateMenu(v,id);
		} else if (c=='d'){
			std::cout << "Delete identity '"+id.name+"'? Y/N " << std::flush;
			auto answer = GetYesNoAnswer();
			std::cout << std::endl;
			if (answer==YesNoAnswer::Yes){
				v.DeleteIdentity(id.name);
				return "Identity '"+id.name+"' deleted.\n";
			}
		} else if (c>='0'&&c<='9'){
			s32 selectIndex = c-'1';
			if (selectIndex<0) selectIndex += 10;
			
			std::string name = id.GetSecretNameFromIndex(selectIndex);
			if (name.empty()){
				continue;
			}
			msg = SecretMenu(v,id,id.secrets.at(name));
		}
	}
	return {};
}

std::string IdentityCreateMenu(Vault& v){
	std::cout << "Enter identity name: ";
	std::string name;
	std::getline(std::cin,name);
	
	TruncateString(name);
	if (name.empty()) return {};
	
	if (v.IdentityExists(name)){
		return "Identity '"+name+"' already exists!";
	}
	
	Identity id{};
	id.name = name;
	id.genTime = GetTime();
	id.secrets = {};
	
	v.AddIdentity(id);
	return "Identity created successfully.";
}

std::string TrySaveVault(Vault& v){
	std::cout << "Save changes? Y/N " << std::flush;
	auto answer = GetYesNoAnswer();
	std::cout << std::endl;
	if (answer!=YesNoAnswer::Yes){
		return "Canceled save.";
	}
	
	
	if (!SaveVault(v)){
		return "Could not save vault!";
	}
	return "Saved successfully.";
}

void VaultMenu(Vault& v){
	u8 c;
	std::string msg = {};
	
	size_t pageIndex = 0;
	while (true){
		size_t idCount = v.identities.size();
		ClearConsole();
		std::cout << "Vault Menu\n";
		DisplayKeyColors(v.key);
		std::cout << "\n\n";
		
		if (!v.identities.empty()){
			std::cout << "Identities:\n";
			auto idIt = v.identities.begin();
			for (size_t i=0;i<pageIndex*10;++i)
				++idIt;
			
			for (size_t i=0;i<10;++i){
				if (idIt==v.identities.end())
					break;
				std::cout << (i+1)%10 << ": " << idIt->first << '\n';
				++idIt;
			}
			if (idCount>10){
				std::cout << "+/-: Next/previous page\n";
				std::cout << "Page " << pageIndex+1 << '\n';
			}
		}
		std::cout << '\n';
		
		std::cout << "i: New identity\n";
		if (v.changed)
			std::cout << "s: Save changes\n";
		std::cout << "q: Quit\n";
		if (!msg.empty())
			std::cout << '\n' << msg << '\n';
		std::cout << std::endl;
		
		
		c = GetKey();
		
		if (c=='q'||c==3||c==27){
			if (!v.changed)
				break;
			
			std::cout << "WARNING: You have unsaved changes.\n";
			std::cout << "Discard changes? Y/N " << std::flush;
			auto answer = GetYesNoAnswer();
			if (answer==YesNoAnswer::Yes){
				std::cout << std::endl;
				break;
			}
		} else if (c=='+'||c=='='){
			++pageIndex;
			pageIndex %= (idCount/10+1);
		} else if (c=='-'||c=='_'){
			--pageIndex;
			pageIndex %= (idCount/10+1);
		} else if (c=='s'&&v.changed){
			msg = TrySaveVault(v);
		} else if (c=='i'){
			msg = IdentityCreateMenu(v);
		} else if (c>='0'&&c<='9'){
			s32 selectIndex = c-'1';
			if (selectIndex<0) selectIndex += 10;
			
			selectIndex += pageIndex*10;
			
			std::string name = v.GetIdentityNameFromIndex(selectIndex);
			if (name.empty()){
				continue;
			}
			msg = IdentityMenu(v,v.identities.at(name));
		}
	}
	std::cout << "Quitting..." << std::endl;
}

