#ifndef ADRENOCHROME_AXE_CONFIG_H
#define ADRENOCHROME_AXE_CONFIG_H

#include <vector>
#include <string>

typedef struct BUILD_CONFIG {

    /*
    BUILD_CONFIG() : sectionNames{".text", ".rdata", ".data"} {}
    std::vector<std::string> sectionNames; // NOTE: section names we want in our final .axe file
    */
    //std::vector<std::string> sectionNames{".text", ".rdata", ".data"}; 
    std::vector<std::string> sectionNames{".text", ".rdata", ".data", ".reloc"};
} BUILD_CONFIG;

#endif