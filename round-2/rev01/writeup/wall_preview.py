import numpy as np
import pylab as pl
from matplotlib import collections  as mc
import random
import math
import json

def fix_endings(x):
    if(x<-100):
        return -100
    if(x>100):
        return 100
    return x

def ccw(A,B,C):
    return (C[1]-A[1]) * (B[0]-A[0]) > (B[1]-A[1]) * (C[0]-A[0])

# Return true if line segments AB and CD intersect
def intersect(A,B,C,D):
    return ccw(A,C,D) != ccw(B,C,D) and ccw(A,B,C) != ccw(A,B,D)


print(intersect([100, 90],[88.437004,73.375420], [90,83], [88,84]))
lines = "{{.start={.x=24,.y=32},.end={.x=100,.y=100}},{.start={.x=-32,.y=-67},.end={.x=-100,.y=-53}},{.start={.x=64,.y=-68},.end={.x=14,.y=-17}},{.start={.x=-97,.y=57},.end={.x=-100,.y=74}},{.start={.x=-92,.y=3},.end={.x=-41,.y=20}},{.start={.x=-54,.y=-1},.end={.x=-47,.y=11}},{.start={.x=-4,.y=39},.end={.x=32,.y=-100}},{.start={.x=60,.y=85},.end={.x=-100,.y=100}},{.start={.x=91,.y=-57},.end={.x=66,.y=-66}},{.start={.x=-62,.y=0},.end={.x=8,.y=-67}},{.start={.x=-21,.y=-12},.end={.x=-41,.y=89}},{.start={.x=56,.y=56},.end={.x=56,.y=58}},{.start={.x=-90,.y=-23},.end={.x=-76,.y=-50}},{.start={.x=48,.y=-70},.end={.x=41,.y=-92}},{.start={.x=56,.y=9},.end={.x=100,.y=68}},{.start={.x=36,.y=44},.end={.x=-30,.y=45}},{.start={.x=34,.y=55},.end={.x=25,.y=49}},{.start={.x=8,.y=59},.end={.x=-27,.y=87}},{.start={.x=70,.y=81},.end={.x=68,.y=81}},{.start={.x=4,.y=33},.end={.x=1,.y=43}},{.start={.x=-46,.y=-68},.end={.x=-58,.y=-100}},{.start={.x=77,.y=17},.end={.x=100,.y=-80}},{.start={.x=1,.y=72},.end={.x=-4,.y=72}},{.start={.x=-48,.y=0},.end={.x=-28,.y=11}},{.start={.x=59,.y=-20},.end={.x=35,.y=-38}},{.start={.x=90,.y=-52},.end={.x=100,.y=-100}},{.start={.x=26,.y=100},.end={.x=-30,.y=100}},{.start={.x=-11,.y=18},.end={.x=-9,.y=43}},{.start={.x=-24,.y=-10},.end={.x=-23,.y=-10}},{.start={.x=72,.y=-4},.end={.x=58,.y=10}},{.start={.x=-65,.y=33},.end={.x=-100,.y=45}},{.start={.x=-47,.y=56},.end={.x=-38,.y=7}},{.start={.x=69,.y=-79},.end={.x=93,.y=-84}},{.start={.x=67,.y=95},.end={.x=54,.y=100}},{.start={.x=-76,.y=51},.end={.x=-79,.y=38}},{.start={.x=93,.y=22},.end={.x=91,.y=6}},{.start={.x=-94,.y=-18},.end={.x=-75,.y=-37}},{.start={.x=37,.y=-28},.end={.x=52,.y=22}},{.start={.x=39,.y=45},.end={.x=21,.y=-13}},{.start={.x=-5,.y=53},.end={.x=1,.y=63}},{.start={.x=-11,.y=20},.end={.x=-26,.y=24}},{.start={.x=86,.y=-98},.end={.x=38,.y=-100}},{.start={.x=-24,.y=80},.end={.x=-25,.y=82}},{.start={.x=9,.y=-74},.end={.x=-33,.y=-82}},{.start={.x=37,.y=-89},.end={.x=34,.y=-57}},{.start={.x=57,.y=60},.end={.x=100,.y=100}},{.start={.x=37,.y=-95},.end={.x=34,.y=-100}},{.start={.x=-87,.y=-17},.end={.x=-89,.y=2}},{.start={.x=23,.y=64},.end={.x=26,.y=51}},{.start={.x=-23,.y=98},.end={.x=56,.y=89}},{.start={.x=24,.y=5},.end={.x=20,.y=15}},{.start={.x=-42,.y=57},.end={.x=-37,.y=59}},{.start={.x=79,.y=-47},.end={.x=72,.y=-58}},{.start={.x=4,.y=0},.end={.x=4,.y=0}},{.start={.x=-94,.y=-44},.end={.x=-95,.y=-54}},{.start={.x=76,.y=-11},.end={.x=45,.y=-4}},{.start={.x=-13,.y=-58},.end={.x=-15,.y=-77}},{.start={.x=81,.y=94},.end={.x=80,.y=100}},{.start={.x=-57,.y=-64},.end={.x=-52,.y=-73}},{.start={.x=-43,.y=45},.end={.x=-34,.y=45}},{.start={.x=14,.y=-19},.end={.x=28,.y=-75}},{.start={.x=8,.y=53},.end={.x=6,.y=56}},{.start={.x=55,.y=75},.end={.x=45,.y=77}},{.start={.x=62,.y=-5},.end={.x=46,.y=-2}},{.start={.x=43,.y=34},.end={.x=58,.y=15}},{.start={.x=-15,.y=3},.end={.x=2,.y=10}},{.start={.x=-84,.y=61},.end={.x=-100,.y=100}},{.start={.x=-74,.y=24},.end={.x=-82,.y=31}},{.start={.x=61,.y=7},.end={.x=73,.y=-5}},{.start={.x=7,.y=120},.end={.x=97,.y=172}},{.start={.x=35,.y=54},.end={.x=47,.y=74}},{.start={.x=-79,.y=-4},.end={.x=-88,.y=-5}},{.start={.x=-63,.y=-28},.end={.x=-65,.y=9}},{.start={.x=53,.y=-28},.end={.x=63,.y=-98}},{.start={.x=92,.y=-85},.end={.x=91,.y=-97}},{.start={.x=46,.y=33},.end={.x=38,.y=38}},{.start={.x=100,.y=44},.end={.x=100,.y=57}},{.start={.x=11,.y=49},.end={.x=31,.y=82}},{.start={.x=37,.y=-45},.end={.x=20,.y=-39}},{.start={.x=-22,.y=-43},.end={.x=-42,.y=-58}},{.start={.x=9,.y=-30},.end={.x=12,.y=-28}},{.start={.x=25,.y=83},.end={.x=25,.y=87}},{.start={.x=70,.y=-93},.end={.x=65,.y=-89}},{.start={.x=-18,.y=-84},.end={.x=25,.y=-81}},{.start={.x=4,.y=-73},.end={.x=23,.y=-73}},{.start={.x=-49,.y=87},.end={.x=-91,.y=85}},{.start={.x=66,.y=-76},.end={.x=62,.y=-73}},{.start={.x=41,.y=100},.end={.x=38,.y=107}},{.start={.x=32,.y=-22},.end={.x=35,.y=-18}},{.start={.x=-67,.y=-84},.end={.x=-72,.y=-100}},{.start={.x=96,.y=10},.end={.x=100,.y=-41}},{.start={.x=27,.y=-52},.end={.x=23,.y=-48}},{.start={.x=71,.y=-86},.end={.x=64,.y=-81}},{.start={.x=-60,.y=-26},.end={.x=-46,.y=-18}},{.start={.x=64,.y=0},.end={.x=65,.y=1}},{.start={.x=-100,.y=57},.end={.x=-99,.y=58}},{.start={.x=-88,.y=30},.end={.x=-85,.y=30}},{.start={.x=73,.y=68},.end={.x=100,.y=100}},{.start={.x=67,.y=15},.end={.x=68,.y=18}},{.start={.x=70,.y=91},.end={.x=78,.y=97}},{.start={.x=-80,.y=-9},.end={.x=-81,.y=-6}},{.start={.x=87,.y=57},.end={.x=73,.y=66}},{.start={.x=69,.y=41},.end={.x=76,.y=41}},{.start={.x=-32,.y=12},.end={.x=-31,.y=11}},{.start={.x=44,.y=44},.end={.x=43,.y=51}},{.start={.x=-31,.y=78},.end={.x=-38,.y=75}},{.start={.x=64,.y=-34},.end={.x=87,.y=-33}},{.start={.x=87,.y=-67},.end={.x=80,.y=-80}},{.start={.x=-49,.y=76},.end={.x=-40,.y=78}},{.start={.x=39,.y=-55},.end={.x=38,.y=-60}},{.start={.x=-13,.y=-52},.end={.x=-22,.y=-45}},{.start={.x=-83,.y=84},.end={.x=-85,.y=75}},{.start={.x=-65,.y=-10},.end={.x=-69,.y=9}},{.start={.x=7,.y=44},.end={.x=2,.y=43}},{.start={.x=78,.y=60},.end={.x=76,.y=48}},{.start={.x=66,.y=-45},.end={.x=85,.y=-37}},{.start={.x=-25,.y=-60},.end={.x=-17,.y=-67}},{.start={.x=25,.y=51},.end={.x=20,.y=47}},{.start={.x=-69,.y=32},.end={.x=-82,.y=9}},{.start={.x=-27,.y=-75},.end={.x=-24,.y=-65}},{.start={.x=41,.y=64},.end={.x=52,.y=61}},{.start={.x=-68,.y=-39},.end={.x=-55,.y=-54}},{.start={.x=-15,.y=-59},.end={.x=-30,.y=-54}},{.start={.x=-61,.y=-55},.end={.x=-60,.y=-52}},{.start={.x=25,.y=-88},.end={.x=23,.y=-83}},{.start={.x=65,.y=37},.end={.x=50,.y=26}},{.start={.x=-20,.y=89},.end={.x=-25,.y=86}},{.start={.x=-52,.y=-81},.end={.x=-60,.y=-66}},{.start={.x=67,.y=72},.end={.x=60,.y=81}},{.start={.x=-79,.y=23},.end={.x=-139,.y=-27}},{.start={.x=-86,.y=-2},.end={.x=-87,.y=-1}},{.start={.x=-100,.y=36},.end={.x=-46,.y=30}},{.start={.x=-92,.y=58},.end={.x=-100,.y=93}},{.start={.x=1,.y=-89},.end={.x=0,.y=-84}},{.start={.x=-83,.y=-16},.end={.x=-66,.y=-51}},{.start={.x=-12,.y=52},.end={.x=-9,.y=54}},{.start={.x=42,.y=81},.end={.x=35,.y=66}},{.start={.x=90,.y=83},.end={.x=88,.y=84}},{.start={.x=87,.y=48},.end={.x=98,.y=51}},{.start={.x=-40,.y=-16},.end={.x=-37,.y=4}},{.start={.x=-55,.y=-78},.end={.x=-75,.y=-74}},{.start={.x=65,.y=23},.end={.x=57,.y=30}},{.start={.x=23,.y=17},.end={.x=18,.y=42}},{.start={.x=34,.y=73},.end={.x=28,.y=75}},{.start={.x=14,.y=97},.end={.x=15,.y=98}},{.start={.x=35,.y=-43},.end={.x=37,.y=-44}},{.start={.x=-38,.y=13},.end={.x=-28,.y=13}},{.start={.x=13,.y=58},.end={.x=11,.y=58}},{.start={.x=-52,.y=-28},.end={.x=-38,.y=-54}},{.start={.x=24,.y=-27},.end={.x=-1,.y=38}},{.start={.x=42,.y=63},.end={.x=45,.y=53}},{.start={.x=0,.y=-14},.end={.x=5,.y=-21}},{.start={.x=40,.y=58},.end={.x=41,.y=59}},{.start={.x=5,.y=10},.end={.x=7,.y=11}},{.start={.x=18,.y=50},.end={.x=13,.y=50}},{.start={.x=56,.y=70},.end={.x=58,.y=78}},{.start={.x=-35,.y=-47},.end={.x=-40,.y=-46}},{.start={.x=-97,.y=-75},.end={.x=-70,.y=-88}},{.start={.x=77,.y=45},.end={.x=59,.y=61}},{.start={.x=-6,.y=-74},.end={.x=5,.y=-67}},{.start={.x=-80,.y=-43},.end={.x=-75,.y=-55}},{.start={.x=34,.y=-8},.end={.x=24,.y=-26}},{.start={.x=87,.y=-80},.end={.x=93,.y=-71}},{.start={.x=-68,.y=66},.end={.x=-60,.y=82}},{.start={.x=71,.y=51},.end={.x=61,.y=62}},{.start={.x=46,.y=-33},.end={.x=52,.y=-33}},{.start={.x=32,.y=38},.end={.x=34,.y=40}},{.start={.x=68,.y=-5},.end={.x=79,.y=-10}},{.start={.x=-47,.y=-91},.end={.x=-49,.y=-97}},{.start={.x=-53,.y=9},.end={.x=-41,.y=14}},{.start={.x=93,.y=-75},.end={.x=92,.y=-75}},{.start={.x=-67,.y=-96},.end={.x=-60,.y=-100}},{.start={.x=21,.y=-30},.end={.x=23,.y=-32}},{.start={.x=7,.y=47},.end={.x=11,.y=55}},{.start={.x=-2,.y=90},.end={.x=27,.y=80}},{.start={.x=67,.y=-65},.end={.x=63,.y=-59}},{.start={.x=-36,.y=100},.end={.x=-39,.y=104}},{.start={.x=21,.y=-75},.end={.x=22,.y=-73}},{.start={.x=-69,.y=2},.end={.x=-68,.y=3}},{.start={.x=22,.y=31},.end={.x=24,.y=42}},{.start={.x=-89,.y=66},.end={.x=-93,.y=64}},{.start={.x=90,.y=51},.end={.x=91,.y=51}},{.start={.x=91,.y=-84},.end={.x=79,.y=-90}},{.start={.x=-41,.y=100},.end={.x=-41,.y=95}},{.start={.x=-23,.y=-61},.end={.x=-22,.y=-59}},{.start={.x=38,.y=46},.end={.x=32,.y=52}},{.start={.x=-39,.y=-24},.end={.x=-41,.y=-4}},{.start={.x=-27,.y=-100},.end={.x=-15,.y=-88}},{.start={.x=88,.y=100},.end={.x=77,.y=104}},{.start={.x=58,.y=36},.end={.x=58,.y=33}},{.start={.x=-24,.y=-26},.end={.x=-22,.y=-32}},{.start={.x=-51,.y=32},.end={.x=-99,.y=57}},{.start={.x=-100,.y=23},.end={.x=-89,.y=24}},{.start={.x=50,.y=-13},.end={.x=56,.y=-11}},{.start={.x=-51,.y=-89},.end={.x=-53,.y=-89}}}".replace(".start={.x=", "").replace(".y=", "").replace("},.end={.x=", "],[").replace("}},{", "]],[[")[2:-3]
lines = json.loads("[[["+lines+"]]]")
#print(lines)

# for x in range(200):
#     newlinestart = np.asarray((random.randint(-100, 100), random.randint(-100, 100)))
#     direction = 2*math.pi*random.randint(0, 360)/360
#     length = random.randint(10, 200)
#     newlineend = np.asarray((fix_endings(math.floor(newlinestart[0]+length*math.cos(direction))), fix_endings(math.floor(newlinestart[1]+length*math.sin(direction)))))
#     fail=False
#     for line in lines:
#         if(intersect(newlinestart, newlineend, line[0], line[1])):
#             d = np.linalg.norm(np.cross(line[1]-line[0], line[0]-newlinestart))/np.linalg.norm(line[1]-line[0])
#             length = d-1
#             #print(length)
#             if(length<=1):
#                 newlinestart = newlineend
#                 direction = math.fabs(direction-math.pi)
#                 d = np.linalg.norm(np.cross(line[1]-line[0], line[0]-newlinestart))/np.linalg.norm(line[1]-line[0])
#                 length = d-1
#                 #print(length)
#                 if(length<=1):
#                     fail=True
#             if(fail):
#                 break
#             newlineend = np.asarray((math.floor(newlinestart[0]+length*math.cos(direction)), math.floor(newlinestart[1]+length*math.sin(direction))))
#     if(fail):
#         continue
#     lines.append([newlinestart, newlineend])

formatted_lines="{"+",".join(f"{{.start={{.x={line[0][0]},.y={line[0][1]}}},.end={{.x={line[1][0]},.y={line[1][1]}}}}}" for line in lines)+"}"
#print(formatted_lines)
lc = mc.LineCollection(lines,linewidths=1)
fig, ax = pl.subplots()
ax.add_collection(lc)
#RIZZTMZZUMZZNAZZSBZZSBZZWHZZIIZZIIZZKVZZUYZZUYOONAGG
ax.autoscale()
ax.margins(0.1)
ax.set_xlim([-110, 110])
ax.set_ylim([-110, 110])
pl.plot(100.000000,90.000000,'ro')
pl.plot(87.500000,68.349365,'ro')
pl.plot(87.500000,68.349365,'ro')
pl.plot(87.460060,51.185081,'ro')
pl.plot(79.955070,48.932774,'ro')
pl.plot(79.955070,48.932774,'ro')
pl.plot(81.392876,43.049538,'ro')
pl.plot(62.472496,42.111511,'ro')
pl.plot(62.472496,42.111511,'ro')
pl.plot(38.068321,41.997929,'ro')
pl.plot(38.557667,41.658463,'ro')
pl.plot(38.557667,41.658463,'ro')
pl.plot(34.343586,29.995995,'ro')
pl.plot(31.164173,17.804214,'ro')
pl.plot(31.164173,17.804214,'ro')
pl.plot(26.882427,5.954489,'ro')
pl.plot(23.753258,-6.044627,'ro')
pl.plot(23.753258,-6.044627,'ro')
pl.plot(30.455359,-14.380355,'ro')
pl.plot(18.593451,-12.942971,'ro')
pl.plot(20.139227,-11.165747,'ro')
pl.plot(20.139227,-11.165747,'ro')
pl.plot(9.494742,11.454929,'ro')
pl.plot(9.494742,11.454929,'ro')
pl.plot(7.933841,14.772015,'ro')
pl.plot(1.740896,35.187386,'ro')
pl.plot(1.740896,35.187386,'ro')
pl.plot(-0.395090,36.427235,'ro')
pl.plot(1.345047,41.849842,'ro')
pl.plot(-2.044960,44.576439,'ro')
pl.plot(-9.313221,39.084724,'ro')
pl.plot(-6.978070,36.647812,'ro')
pl.plot(-6.978070,36.647812,'ro')
pl.plot(1.627074,13.175457,'ro')
pl.show()