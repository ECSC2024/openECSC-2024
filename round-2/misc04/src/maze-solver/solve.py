import requests
from mazelib.mazelib import Maze
from mazelib.generate.Prims import Prims
from mazelib.solve.ShortestPath import ShortestPath

ENDPOINT = "http://localhost:5000/maze"

"""
maze = Maze(1337)
maze.generator = Prims(50, 50)
maze.generate()
maze.generate_entrances()
maze.solver = ShortestPath()
maze.solve()
"""


class MazeNoComputation:
    start = (65, 0)
    end = (43, 100)  # The real end is (43, 99)
    solutions = [
        [
            (65, 1),
            (66, 1),
            (67, 1),
            (67, 2),
            (67, 3),
            (67, 4),
            (67, 5),
            (66, 5),
            (65, 5),
            (65, 6),
            (65, 7),
            (65, 8),
            (65, 9),
            (65, 10),
            (65, 11),
            (65, 12),
            (65, 13),
            (64, 13),
            (63, 13),
            (63, 14),
            (63, 15),
            (63, 16),
            (63, 17),
            (63, 18),
            (63, 19),
            (63, 20),
            (63, 21),
            (63, 22),
            (63, 23),
            (64, 23),
            (65, 23),
            (65, 24),
            (65, 25),
            (65, 26),
            (65, 27),
            (65, 28),
            (65, 29),
            (66, 29),
            (67, 29),
            (68, 29),
            (69, 29),
            (69, 30),
            (69, 31),
            (69, 32),
            (69, 33),
            (68, 33),
            (67, 33),
            (67, 34),
            (67, 35),
            (67, 36),
            (67, 37),
            (67, 38),
            (67, 39),
            (66, 39),
            (65, 39),
            (65, 40),
            (65, 41),
            (65, 42),
            (65, 43),
            (65, 44),
            (65, 45),
            (65, 46),
            (65, 47),
            (65, 48),
            (65, 49),
            (65, 50),
            (65, 51),
            (65, 52),
            (65, 53),
            (65, 54),
            (65, 55),
            (66, 55),
            (67, 55),
            (67, 56),
            (67, 57),
            (68, 57),
            (69, 57),
            (69, 58),
            (69, 59),
            (70, 59),
            (71, 59),
            (71, 60),
            (71, 61),
            (71, 62),
            (71, 63),
            (72, 63),
            (73, 63),
            (73, 64),
            (73, 65),
            (73, 66),
            (73, 67),
            (73, 68),
            (73, 69),
            (72, 69),
            (71, 69),
            (71, 70),
            (71, 71),
            (71, 72),
            (71, 73),
            (70, 73),
            (69, 73),
            (68, 73),
            (67, 73),
            (67, 74),
            (67, 75),
            (66, 75),
            (65, 75),
            (64, 75),
            (63, 75),
            (62, 75),
            (61, 75),
            (60, 75),
            (59, 75),
            (59, 76),
            (59, 77),
            (59, 78),
            (59, 79),
            (59, 80),
            (59, 81),
            (59, 82),
            (59, 83),
            (59, 84),
            (59, 85),
            (59, 86),
            (59, 87),
            (59, 88),
            (59, 89),
            (59, 90),
            (59, 91),
            (59, 92),
            (59, 93),
            (58, 93),
            (57, 93),
            (57, 94),
            (57, 95),
            (56, 95),
            (55, 95),
            (55, 94),
            (55, 93),
            (54, 93),
            (53, 93),
            (52, 93),
            (51, 93),
            (50, 93),
            (49, 93),
            (49, 92),
            (49, 91),
            (48, 91),
            (47, 91),
            (46, 91),
            (45, 91),
            (44, 91),
            (43, 91),
            (43, 92),
            (43, 93),
            (43, 94),
            (43, 95),
            (43, 96),
            (43, 97),
            (43, 98),
            (43, 99),
        ]
    ]
maze = MazeNoComputation()
solution = maze.solutions[0]

s = requests.Session()
session = {"position": maze.start}

r = s.get(ENDPOINT, params={"direction": "start"})

direction = None
i = 0
while i < len(solution):
    move = solution[i]
    if move[0] == session["position"][0] + 1:
        direction = "down"
    elif move[0] == session["position"][0] - 1:
        direction = "up"
    elif move[1] == session["position"][1] + 1:
        direction = "right"
    elif move[1] == session["position"][1] - 1:
        direction = "left"
    if direction is None:
        break

    r = s.get(ENDPOINT, params={"direction": direction})
    if "FAILED" not in r.text:
        i += 1
        session["position"] = move

print(r.text)
