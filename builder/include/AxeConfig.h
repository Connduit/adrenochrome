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
    // TODO: put all section names in here to see why we can't execute at entry point?
    //std::vector<std::string> sectionNames{".text", ".rdata", ".data", ".reloc", ".pdata", ".rsrc"};
} BUILD_CONFIG;

#endif