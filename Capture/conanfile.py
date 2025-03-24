from conan import ConanFile
from conan.tools.cmake import cmake_layout
import os
 
class ExampleRecipe(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"
 
    def requirements(self):
        self.requires("libpcap/1.10.5")
 
    def layout(self):
        self.folders.build="build"
        self.folders.generators=os.path.join("build","dependencies")
