from flask import Flask, request, make_response
import os, binascii

app = Flask(__name__)

username = "admin"
password = "admin"

def generate_html(message=""):
    return f"""<html>
    <head>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/css/bootstrap.min.css" integrity="sha512-jnSuA4Ss2PkkikSOLtYs8BlYIeeIK1h99ty4YfvRPAlzr377vr3CXDb7sb7eEEBYjDtcYj+AjBH3FLv5uSJuXg==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    </head>
    <body class="d-flex align-items-center py-4 bg-body-tertiary">
        <main class="w-100 m-auto" style="max-width: 330px;">
            <form method="post">
                <h1 class="h3 mb-3 fw-normal">Please sign in</h1>
                <div class="form-floating mb-3">
                    <input type="text" class="form-control" id="username" name="username" placeholder="Username">
                    <label for="username">Username</label>
                </div>
                <div class="form-floating mb-3">
                    <input type="password" class="form-control" id="password" name="password" placeholder="Placeholder">
                    <label for="password">Password</label>
                </div>
                <div class="form-floating mb-3">
                    <input type="text" class="form-control" id="totp" name="totp" placeholder="2FA">
                    <label for="totp">2FA</label>
                </div>
                <button class="btn btn-primary w-100 py-2" type="submit">Sign in</button>
                {message}
            </form>
        </main>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.3/js/bootstrap.min.js" integrity="sha512-ykZ1QQr0Jy/4ZkvKuqWn4iF3lqPZyij9iRv6sGqLRdTPkY69YX6+7wvVGmsdBbiIfN/8OdsI7HABjvEok6ZopQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    </body>
</html>"""

@app.get("/")
def index():
    return generate_html()

@app.post("/")
def login():
    '''
    resp = make_response(generate_html('<div class="alert alert-success mt-3" role="alert">Welcome, now visit <a href="/flag">/flag</a></div>'))
    resp.set_cookie("session", "d6f816cd031715f733539affe057b5103530c23ff9aa01c5c4e71990ac2ae2ac")
    return resp
    '''
    
    if request.form["username"] == username and request.form["password"] == password:
        return generate_html('<div class="alert alert-danger mt-3" role="alert">Invalid 2FA (TOTP)</div>')

    return generate_html('<div class="alert alert-danger mt-3" role="alert">Invalid credentials</div>')

@app.get("/flag")
def flag():
    if request.cookies.get("session") == "d6f816cd031715f733539affe057b5103530c23ff9aa01c5c4e71990ac2ae2ac":
        #return "The flag will appear here after the start of the CTF"
        return "flag{y0u_see_th4t_w4s_3asy_e348db9c}"

    return "You are not authenticated"
