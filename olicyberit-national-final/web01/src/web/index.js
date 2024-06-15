const express = require('express');
const { JSFuck } = require('./jsfuck.js');
const crypto = require('node:crypto');

const port = 3000;

const app = express();
app.set('view engine', 'ejs');
app.use(express.static('public'));

function generateFlag(req) {
	const flag = (process.env.FLAG || 'flag{redacted_[RANDOM]}').replace(
		'[RANDOM]',
		'3e08fd31'
	);
	return flag;
}

app.get('/', (req, res) => {
	const flag = generateFlag(req);

	const jsf = JSFuck.encode(`() => { if (flag.value === "${flag}") { win() } else { loose() } }`, true, true);

	res.render('index', { jsf });
});

app.listen(port, () => {
	console.log(`App listening on port ${port}`);
});
