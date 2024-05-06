from flask import Flask, session, request
from flask_session import Session
from maze import maze
import random, os, binascii

app = Flask(__name__)

app.secret_key = "super_secret_key_asdvbuiwebdwui"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.get("/")
def index():
    return """<html>
<head>
<style>
    #container {
        text-align: center;
    }
    button {
        margin: 10px;
        padding: 10px 20px;
        font-size: 16px;
    }
</style>
</head>
<body>
<div id="container">
    <h2>Blind Maze</h2>
    <form action="/maze" method="get">
        <button type="submit" name="direction" value="start">START</button><br>
    </form>
</div>
</body>
</html>"""


@app.get("/maze")
def move():
    last_move = str(request.args.get("direction"))

    if request.args.get("direction") == "start":
        session["position"] = maze.start
    elif random.randint(0, 100) < 15:
        last_move = "FAILED because the maze was busy. Try the move again!"  
    elif request.args.get("direction") == "up":
        if not "position" in session:
            last_move = "FAILED because you need to start the maze first!"
        elif maze.grid[session["position"][0] - 1][session["position"][1]] == 0:
            session["position"] = (session["position"][0] - 1, session["position"][1])
    elif request.args.get("direction") == "down":
        if not "position" in session:
            last_move = "FAILED because you need to start the maze first!"
        elif maze.grid[session["position"][0] + 1][session["position"][1]] == 0:
            session["position"] = (session["position"][0] + 1, session["position"][1])
    elif request.args.get("direction") == "left":
        if not "position" in session:
            last_move = "FAILED because you need to start the maze first!"
        elif maze.grid[session["position"][0]][session["position"][1] - 1] == 0:
            session["position"] = (session["position"][0], session["position"][1] - 1)
    elif request.args.get("direction") == "right":
        if not "position" in session:
            last_move = "FAILED because you need to start the maze first!"
        elif maze.grid[session["position"][0]][session["position"][1] + 1] == 0:
            session["position"] = (session["position"][0], session["position"][1] + 1)

    if "position" in session and session["position"] == (
        maze.end[0],
        maze.end[1] - 1,
    ):  # The real end is (43, 99)
        return "Here is the FLAG: openECSC{i_found_a_map_" + binascii.b2a_hex(os.urandom(4)).decode() + "}"

    return (
        """<html>
<head>
<style>
    #container {
        text-align: center;
    }
    button {
        margin: 10px;
        padding: 10px 20px;
        font-size: 16px;
    }
</style>
</head>
<body>
<div id="container">
    <h2>Directional Movement Control</h2>
    <h4>Last Move: """
        + last_move
        + """</h4>
    <form action="/maze" method="get">
        <button type="submit" name="direction" value="up">Up</button><br>
        <button type="submit" name="direction" value="left">Left</button>
        <button type="submit" name="direction" value="right">Right</button><br>
        <button type="submit" name="direction" value="down">Down</button><br>
        <button type="submit" name="direction" value="start">Reset</button>
    </form>
</div>

</body>
</html>"""
    )
