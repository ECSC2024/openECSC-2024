const socket = io();
function start() {
    socket.emit("start", function () { });
    console.log('start')
};
let wa = undefined;

async function main() {
    wa = await WebAssembly.instantiateStreaming(fetch('/static/pow.wasm'), { js: { mem: new WebAssembly.Memory({ initial: 0 }) } });
}
main()


let started = false;
let timerInterval = null;
let responseReady = false;
let _socket = null;
let _data = null;


$(document).ready(function () { });
socket.on("connect", () => {
    console.log("connected");
    document.getElementById("header").innerHTML = "Server online";
    document.getElementById("status").style.backgroundColor = "green";
});


socket.on("disconnect", () => {
    console.log("disconnected");
    document.getElementById("header").innerHTML = "Server offline";
    document.getElementById("status").style.backgroundColor = "red";
});


function displayMsg(msg) {
    document.getElementById('main').innerHTML = `<div>${msg}</div>\n<button class="btn btn-primary" onClick="location.reload()">Home</button>`;
}

function respond(e) {
    console.log('respond')
    if (e) {
        e.preventDefault();
    }
    let pow = _data.pow;
    let resp = wa.instance.exports.solve_pow(BigInt(pow.a), BigInt(pow.b), BigInt(pow.c), BigInt(pow.d));
    resp = Number(resp);
    console.log(resp);
    _socket.send({'pow_response': resp, "operation_response": +document.getElementById('response').value });
}

socket.on("message", function (data) {
    console.log('got data')
    console.log(data)
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
        document.getElementById('main').innerHTML = `<div>${operation.a} ${operation.o} ${operation.b}</div>\n<form onSubmit="respond(event)"><input id="response"></input></form>\n<button class="btn btn-primary" onClick="respond()">Submit</button>`;
        document.getElementById('response').focus();
    }

    else {
        displayMsg(data.message);
    }
});