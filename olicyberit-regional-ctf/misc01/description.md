Revolutionary file repositiory with sensitive file protection

```python
bannedwords = ['flag', 'secret', 'password', 'key']

# The user input is cleaned up from banned words
def cleanup(filename):
  for word in bannedwords:
    filename = filename.replace(word, '')
  return filename
```

`nc secure-filemanager.challs.olicyber.it 38104`
