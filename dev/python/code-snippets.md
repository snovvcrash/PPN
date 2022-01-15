# Code Snippets

Run OS command:

{% code title="runCmd.py" %}
```python
import subprocess, shlex

def run_command(command):
	process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE)
	while True:
		output = process.stdout.readline().decode()
		if output == '' and process.poll() is not None:
			break
		if output:
			print(output.strip())
	rc = process.poll()
	return rc
```
{% endcode %}
