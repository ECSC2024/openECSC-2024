import express from 'express';
import bodyParser from 'body-parser';
import middleFilter from './filter.js';
import { sql } from './db.js';

const app = express();
const port = 3000;

app.set('view engine', 'ejs');

app.use(express.static('public'));
app.use(bodyParser.json());
app.use(middleFilter);

app.get('/', (req, res) => {
	res.render('index');
});

app.get('/post/:id', (req, res) => {
	res.render('post', { id: req.params.id });
});

app.post('/api/posts', async (req, res) => {
	try {
		if (!req.body) {
			res.status(400).send('Bad request');
			return;
		}

		const data = req.body;

		if (!data.fields || !Array.isArray(data.fields)) {
			res.status(400).send('Bad request');
			return;
		}

		// Is this how graphql works?
		const fields = data.fields.filter((field) => typeof field === 'string');
		const posts = await sql(`SELECT ${fields.join(', ')} FROM posts`);

		res.send(posts);
	} catch (e) {
		res.send(e);
	}
});

app.post('/api/post/:id', async (req, res) => {
	try {
		if (!req.body) {
			res.status(400).send('Bad request');
			return;
		}

		const data = req.body;

		if (!data.fields || !Array.isArray(data.fields)) {
			res.status(400).send('Bad request');
			return;
		}

		// Is this how graphql works?
		const fields = data.fields.filter((field) => typeof field === 'string');
		const posts = await sql(`SELECT ${fields.join(', ')} FROM posts WHERE id = ${req.params.id}`);

		res.send(posts[0]);
	} catch (e) {
		res.send(e);
	}
});

app.listen(port, () => {
	console.log(`App listening on port ${port}`);
});
