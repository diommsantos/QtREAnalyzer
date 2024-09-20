# QtREAnalyzer
QtREAnalyzer is a Ghidra Analyzer that analyzes binaries that use the Qt framework. It recovers Qt specific objects not recovered byt Ghidra. Work is in progress to recover function signatures and propertie names from the Qt metadata, see .

# Installation

This analyzer is tied to the Ghidra version it is being installed on. Currently is necessary to build it;
built extensions will be provided in the future for the latest Ghidra versions. 

## Build the Ghidra extension

1. Install [gradle](https://docs.gradle.org/current/userguide/installation.html#ex-installing-manually)
2. Navigate to the `QtREAnalyzer\QtREAnalyzer` folder

```bash
cd QtREAnalyzer\QtREAnalyzer
```
 
3. Build the plugin for your Ghidra installation (replace `$GHIDRA_DIR` with your installation directory).
For example, if you have the following Ghidra installation path `C:\ghidra_11.0.3_PUBLIC` you would run 
``gradle -PGHIDRA_INSTALL_DIR=C:\ghidra_11.0.3_PUBLIC``. 

```bash
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_DIR
```

## Install the Analyzer

1. From Ghidra projects manager: ``File`` -> ``Install Extensions...``, click on the
   `+` sign and select the `QtREAnalyzer\QtREAnalyzer\dist\ghidra_*_QtREAnalyzer.zip` and click OK.
2. Restart Ghidra as requested

## Troubleshooting
To verify QtREAnalyzer is correctly installed, you can open CodeBrowser and select
``Analysis`` -> ``Auto Analyze ... A`` and check that the `QtReAnalyzer` option
exists.

# Usage
![QtREAnalyzer Usage](/docs/QtREAnalyzer_usage.gif)

# TODO
- [ ] Recover function signatures from Qt metadata.
- [ ] Recover properties names and types from Qt metadata.
- [ ] Recover connections between signals and slots.
- [ ] Identify and recover more Qt classes and methods.

# Limitations

Currently QtREAnalyzer only works with x32 or x64 binaries that have RTTI (i.e compiled with the MSVC compiler). This is so since QtREAnalyzer uses RTTI to find if classes inherit from QObject. This said if one wants to extend this analyzer to work with binaries without RTTI all that is necessary to do is modify the ``RttiClass.java`` file appropriately.

# Acknowledgments

QtREAnalyzer would have not been possible without the following amazing resources:

- https://www.usenix.org/conference/usenixsecurity23/presentation/wen and its github page https://github.com/OSUSecLab/QtRE
- https://ktln2.org/reversing-c%2B%2B-qt-applications-using-ghidra/
- https://woboq.com/blog/how-qt-signals-slots-work.html
- https://www.codeproject.com/articles/31330/qt-internals-reversing