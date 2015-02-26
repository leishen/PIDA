# PIDA
Python usability wrapper for IDA Pro

Installation
------------
To install, copy to $APPDATA\Hex-Rays\idapythonrc.py.  IDA Pro loads this file upon initialization of idapython. 


Examples
--------
```

func = Function(ScreenEA())
func.call_tree()
```

