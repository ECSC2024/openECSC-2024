package main

import "fmt"

type Move struct {
	x, y int
}

type JumpUp struct {
	times int
}

type JumpDown struct {
	times int
}

type Teleport struct {
	magic int
}

type Position struct {
	x, y, l int
}

var targets = []Position{
	/* TARGETS */
}

func main() {
	var flag string
	_, _ = fmt.Scanf("%s", &flag)

	var ops []any
	for _, c := range []byte(flag) {
		switch c & 3 {
		case 0:
			ops = append(ops, &Move{int((c >> 2) & 0b111), int(c >> 5)})
		case 1:
			ops = append(ops, &JumpUp{int(c >> 2)})
		case 2:
			ops = append(ops, &JumpDown{int(c >> 2)})
		case 3:
			ops = append(ops, &Teleport{int(c >> 2)})
		}
	}

	score := 0
	var curr Position
	for i, op := range ops {
		switch op := op.(type) {
		case *Move:
			curr.x += op.x
			curr.y += op.y
		case *JumpUp:
			curr.l += op.times
		case *JumpDown:
			curr.l -= op.times
		case *Teleport:
			curr.x = curr.x ^ op.magic
			curr.y = curr.y ^ op.magic
			curr.l = curr.l ^ op.magic
		}

		if i < len(targets) && curr == targets[i] {
			score++
		}
	}

	if score == len(targets) {
		println("correct")
	} else {
		println("wrong")
	}
}
