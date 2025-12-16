#include "builder.h"

#include <iostream>

int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		std::cout << "Not enough arguements" << std::endl;
	}
	else if (argc == 2)
	{
		AdrenochromeBuilder builder;
		// NOTE: just assume all argv values will be in ascii... TODO: don't assume this 
		std::string s = argv[1];
		std::wstring ws(s.begin(), s.end());
		const wchar_t *path = ws.c_str();
		builder.loadFile(path);
		//AdrenochromeBuilder::loadFile(argv[1]);
	}

}
