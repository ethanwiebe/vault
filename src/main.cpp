#include "plat.h"
#include "vault.h"

bool gDebug = false;

int main(int argc,char** argv){
	std::cout.sync_with_stdio(false);
	PlatInit();
	
	Vault v;
	std::string path;

	if (argc==1){
		if (!CreateVault(v)){
			std::cout << "Could not create vault!" << std::endl;
			exit(1);
		}
	} else {
		std::string arg = std::string(argv[1]);
		if (arg=="-h" || arg=="--help"){
			DisplayHelpMessage();
			exit(0);
		} else {
			if (!LoadVault(v,arg)){
				exit(1);
			}
		}
	}
	
	VaultMenu(v);
	return 0;
}
