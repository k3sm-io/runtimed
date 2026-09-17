package sandbox

// ServerSubdir stands in for the real pkg/sandbox *Subdir consts declared in
// an ungated file.
const ServerSubdir = "server"

// StraySubdir is the deliberately unreferenced const this fixture exercises:
// its name appears in the fake test file's comments only, never in code, so
// the scanner must still report it missing.
const StraySubdir = "stray"
