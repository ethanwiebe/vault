#include "plat.h"
#include "vault.h"

int main(int argc,char** argv){
	//std::cout.sync_with_stdio(false);
	PlatInit();
	
	Vault v;
	std::string path;

	if (argc==1){
		if (!CreateVault(v)){
			exit(1);
		}
	} else {
		std::string arg = std::string(argv[1]);
		if (arg=="-h" || arg=="--help"){
			DisplayHelpMessage();
			exit(0);
		} else {
			v.path = arg;
			if (!LoadVault(v)){
				exit(1);
			}
		}
	}
	
	VaultMenu(v);
	
	return 0;
}
