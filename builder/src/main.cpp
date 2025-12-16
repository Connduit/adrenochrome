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
		AdrenochromeBuilder::loadFile(argv[1]);
	}

}
