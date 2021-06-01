# Python




## pip

Freeze dependencies:

```
$ pip freeze --local [-r requirements.txt] > requirements.txt
```




## Linting



### flake8

```
$ python3 -m flake8 --ignore=W191,E501,E722 somefile.py
```

{% code title="SublimeLinter.sublime-settings" %}
```json
{
	"linters": {
		"flake8": {
			"args": ["--ignore=W191,E501,E722"]
		}
	}
}
```
{% endcode %}



### pylint

```
$ python3 -m pylint --disable=W0311,C0301,R0912,R0915,C0103,C0114,R0903 --msg-template='{msg_id}:{line:3d},{column:2d}:{obj}:{msg}' somefile.py
```

{% code title="SublimeLinter.sublime-settings" %}
```json
{
	"linters": {
		"pylint": {
			"disable": true,
			"args": ["--disable=W0311,C0301,R0912,R0915,C0103,C0114,R0903"]
		}
	}
}
```
{% endcode %}




## PyPI



### twine

```
$ python setup.py sdist bdist_wheel [--bdist-dir ~/temp/bdistwheel]
$ twine check dist/*
$ twine upload --repository-url https://test.pypi.org/legacy/ dist/*
$ twine upload dist/*
```




## Misc



### Fix Python 2.7 Registry

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Python\PythonCore\2.7]

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Python\PythonCore\2.7\Help]

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Python\PythonCore\2.7\Help\MainPythonDocumentation]
@="C:\\Python27\\Doc\\python26.chm"

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Python\PythonCore\2.7\InstallPath]
@="C:\\Python27\\"

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Python\PythonCore\2.7\InstallPath\InstallGroup]
@="Python 2.7"

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Python\PythonCore\2.7\Modules]

[HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Python\PythonCore\2.7\PythonPath]
@="C:\\Python27\\Lib;C:\\Python27\\DLLs;C:\\Python27\\Lib\\lib-tk"
```
