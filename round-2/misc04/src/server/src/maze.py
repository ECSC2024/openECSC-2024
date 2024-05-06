from mazelib.mazelib import Maze
from mazelib.generate.Prims import Prims


maze = Maze(1337)
maze.generator = Prims(50, 50)
maze.generate()
maze.generate_entrances()

maze_grid = []
for row in maze.grid:
    maze_grid.append("".join([str(i) for i in row]))
