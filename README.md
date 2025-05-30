# QtREAnalyzer

QtREAnalyzer is a Ghidra Analyzer designed to reverse-engineer binaries that utilize the Qt framework. Its primary function is to recover Qt-specific object and method information, providing valuable insights into binary structures.

# Features

- Works on binaries without debug symbols.
- Identifies and labels staticMetaObject objects created by  the Qt moc.
- Identifies and labels qt_meta_stringdata objects created by the Qt moc.
- Identifies and labels qt_meta_data objects created by the Qt moc.
- Identifies and labels qt_static_metacall functions created by the Qt moc.
- Annotates with comments the previously identified qt_static_metacall functions with the methods and propertie signatures recovered from the Qt meta data.
- Identifies and applies method signatures, i.e. Qt methods (signals and slots) get their original name, parameter types and sometimes parameter names depending on the available metadata.
- Identifies and applies propertie names and types to the base Qt class, i.e. Qt properties get their original name and sometimes full types depending on the available metadata, and are created in the class data type they belong to.

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
- [x] Automatically apply function signatures recovered from Qt metadata, see [1](https://www.usenix.org/conference/usenixsecurity23/presentation/wen).
- [x] Automatically apply properties names and types from Qt metadata, see [1](https://www.usenix.org/conference/usenixsecurity23/presentation/wen).
- [ ] Recover connections between signals and slots.
- [ ] Identify and recover more Qt classes and methods.

# Limitations

Currently QtREAnalyzer only works with x32 or x64 binaries that have RTTI (i.e compiled with the MSVC compiler). This is so since QtREAnalyzer uses RTTI to find if classes inherit from QObject. This said if one wants to extend this analyzer to work with binaries without RTTI all that is necessary to do is modify the ``RttiClass.java`` file appropriately.

In very rare cases an incorrect signature will be applied to a function or a property will be added to a data type in the incorrect address. This is almost impossible to fix since the way QtREAnalyzer maps Qt signals, slots and propertie signatures to the corresponding function address/propertie offset is heuristic based. This shouldn't be a major limitation, in a file with over 10 000 Qt signals and slots checking manually a substantial sample I only found a handful of erroneously labeled symbols.

# Acknowledgments

QtREAnalyzer would have not been possible without the following amazing resources:

- The [article](https://www.usenix.org/conference/usenixsecurity23/presentation/wen) "Egg Hunt in Tesla Infotainment: A First Look at Reverse Engineering of Qt Binaries" by Wen, Haohuang and Lin, Zhiqiang and its [github repository](https://github.com/OSUSecLab/QtRE)
- https://ktln2.org/reversing-c%2B%2B-qt-applications-using-ghidra/
- https://woboq.com/blog/how-qt-signals-slots-work.html
- https://www.codeproject.com/articles/31330/qt-internals-reversing
