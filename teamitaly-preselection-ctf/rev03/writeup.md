# TeamItaly Preselection CTF 2024

## [rev] Calculations x100 (0 solves)

I recently found my childhood console again, let's see if you can beat my Brain Age record!

Site: [http://calculationsx100.challs.external.open.ecsc2024.it](http://calculationsx100.challs.external.open.ecsc2024.it)

Authors: Matteo Protopapa <@matpro>, Alberto Carboneri <@Alberto247>

## Overview

The challenge is a simple implementation of "Brain Age", a game where the user is supposed to quickly solve several mathematical problems in a row.
The challenge's attachments consist of only a link to a website, implementing the game.
Upon visiting with a browser, we are greeted with a "Start" button which, when pressed, starts a countdown and provides the first problem.

The goal of the challenge is to solve 100 problems in 100 seconds to get the flag.

## Solution

A first, possible approach, to the challenge is implementing a "monkey patch" to quickly solve the provided problems. However, one quickly finds out that after about 50 problems the browser starts to hang and it is impossible to keep up with the timer.
We need to analyze the code of the page to find out what is causing the issue and find a way to solve it.

By opening the developer console we can find a JavaScript file, containing the core of the logic, the code to connect to the websocket, and a call to an external web assembly file `pow.wasm`.
In fact, we can see that the server, for each round, provides us with a Proof of Work other than the problem to solve.
This PoW is handled by the wasm code, which turns out to be too slow to complete in time with large values.

We need to reverse engineer the WebAssembly and attempt to optimize it.
Several tools can be found to analyze the code. For example, [wabt](https://github.com/WebAssembly/wabt/blob/main/docs/decompiler.md) provides a partial decompiler.

By analyzing the code, we can sort of understand what the PoW is actually doing and try to optimize it.
Specifically we can find that `f1` is calculating the multiplicative inverse and `f3` is evaluating the binomial coefficient of its parameters.
One possible approach is to attempt to speed up the code by pre-calculating the result of functions `f1`, `f2`, and `f3` for most values, and using this cache during the solution.
The other, harder to find, approach, was recognizing the PoW to be the "unoptimized" side of the [Rothe-Hagen identity](https://en.wikipedia.org/wiki/Rothe%E2%80%93Hagen_identity). In order to speed up calculations one can simply replace the whole PoW code with the "fast" side of it.

Unfortunately, as specified in the challenge's description, only browsers are officially supported by the remote server, so implementing the solution using external libraries won't work as we will just receive a "Browser not supported" message from the remote.
In order to overcome this limitation we can simply implement the whole solution in JavaScript and have it running inside our browser using the developer console.

## Exploit

```javascript
function solve() {
    const socket = io();
    function start() {
        socket.emit("start", function () { });
        console.log('start')
    };

    let started = false;
    let timerInterval = null;
    let responseReady = false;
    let _socket = null;
    let _data = null;


    socket.on("connect", () => {
        console.log("connected");
        document.getElementById("header").innerHTML = "Server online";
        document.getElementById("status").style.backgroundColor = "green";
        start();
    });


    socket.on("disconnect", () => {
        console.log("disconnected");
        document.getElementById("header").innerHTML = "Server offline";
        document.getElementById("status").style.backgroundColor = "red";
    });


    function displayMsg(msg) {
        document.getElementById('main').innerHTML = `<div>${msg}</div>\n<button class="btn btn-primary" onClick="location.reload()">Home</button>`;
    }

    const M = BigInt(10**9 + 7);

    function xgcd(a, b) {
        a = BigInt(a);
        b = BigInt(b);
        if (b == 0) {
        return [1, 0, a];
        }

        temp = xgcd(b, a % b);
        x = temp[0];
        y = temp[1];
        d = temp[2];
        return [Number(y), Number(x-y*Math.floor(Number(a/b))), Number(d)];
    }

    function fac(n, k=1){
        n = BigInt(n);
        let r = 1n;
        while(n > k){
            r *= n;
            r %= M;
            n -= 1n;
        }
        return r;
    };

    function bincoeff(n, k){
        if (n < k){
            return 0;
        }

        n = Number(n);
        k = Number(k);
        k = Math.min(k, n-k);
        n = BigInt(n);
        k = BigInt(k);

        let res = BigInt((fac(n, n-k) * BigInt(xgcd(fac(k), M)[0])) % M);
        return Number((res + M) % M);
    }

    function solve_pow(a, b, c, d) {
        let res = BigInt((a+b) * BigInt(xgcd(a+b+d*c, M)[0]));
        res = (res + M) % M;
        res = res * BigInt(bincoeff(a+b+d*c, d));
        while (res < 0){
            res = (res+M) % M
        }
        return Number(res % M);
    }

    function solve_op(a, b, o){
        switch(o){
            case '+':
                return a+b;
            case '-':
                return a-b;
            case '*':
                return a*b;
            case '/':
                return Math.floor(a/b);
        }
    }

    socket.on("message", function (data) {
        console.log('got data', data)
        if (!started) {
            timerInterval = setInterval(() => {
                let c = document.getElementById('clock');
                let s = +c.innerText;
                c.innerText = s - 1;
                if (s <= 1 && timerInterval) {
                    clearInterval(timerInterval);
                    displayMsg("Too slow!");
                }
            }, 1000)
            started = true;
        }

        if (data.type == 'calculation') {
            let operation = data.operation;
            responseReady = false;
            _socket = socket;
            _data = data;
            let pow = _data.pow;
            let pow_resp = solve_pow(BigInt(pow.a), BigInt(pow.b), BigInt(pow.c), BigInt(pow.d));
            pow_resp = Number(pow_resp);
            let op_resp = solve_op(operation.a, operation.b, operation.o);
            _socket.send({ 'pow_response': pow_resp, "operation_response": op_resp });
        }

        else {
            displayMsg(data.message);
        }
    });
}
solve()
```
