import math

strength = int(input("strength(0-25): "))

direction = int(input("direction(degrees): "))

direction = (direction/360)

istrength = round((strength/25)*675)
idirection = round((direction)*675)

assert 0<=istrength<=675
assert 0<=idirection<=675

sstrength = chr(math.floor(istrength/26)+65)+chr((istrength%26)+65)
sdirection = chr(math.floor(idirection/26)+65)+chr((idirection%26)+65)

print(sdirection+sstrength)