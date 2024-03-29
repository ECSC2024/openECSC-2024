const express = require('express');
const crypto = require('crypto');
const sanitizer = require("perfect-express-sanitizer");

let products = require('./products');

const HEADLESS_HOST = process.env.HEADLESS_HOST || 'headless:5000';
const HEADLESS_AUTH = process.env.HEADLESS_AUTH || 'supersecret';
const WEB_DOM = process.env.WEB_DOM || 'web:3000';
const FLAG = process.env.FLAG || 'openECSC{this_is_a_fake_flag}';
const admin_password = crypto.randomBytes(20).toString('hex');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.set('view engine', 'ejs');
app.use(sanitizer.clean({ xss: true }, ["/admin"]));

app.use((req, res, next) => {
    res.locals.errormsg = '';
    res.locals.successmsg = '';
    next();
});

app.get('/', (req, res) => {
    res.render('products', { products: products });
});

app.get('/product/:id', (req, res) => {
    const id = parseInt(req.params.id);

    if (isNaN(id) || id < 0 || id >= products.length) {
        res.status(404).send('Not found');
        return;
    }

    res.render('product', { product: products[id] });
});

app.get('/search', (req, res) => {
    let query = req.query.q || '';

    if (query.length > 50) {
        res.locals.errormsg = 'Search query is too long';
        query = '';
    }

    const result = products.filter(product => product.name.toLowerCase().includes(query.toLowerCase()));

    res.render('search', { products: result, query: query });
});

app.get('/admin', (req, res) => {
    res.render('admin', { products: products });
});

app.get('/admin/:id', (req, res) => {
    const id = parseInt(req.params.id);

    if (isNaN(id) || id < 0 || id >= products.length) {
        res.status(404).send('Not found');
        return;
    }

    res.render('edit_product', { product: products[id] });
});

app.post('/admin/:id', (req, res) => {
    const id = parseInt(req.params.id);

    if (isNaN(id) || id < 0 || id >= products.length) {
        res.status(404).send('Not found');
        return;
    }

    if (req.body.password !== admin_password) {
        res.locals.errormsg = 'Invalid password';
        res.render('edit_product', { product: products[id] });
        return;
    }

    if (req.body.name) {
        products[id].name = req.body.name;
    }

    if (req.body.description) {
        products[id].description = req.body.description;
    }

    const price = parseFloat(req.body.price);
    if (!isNaN(price) && price >= 0) {
        products[id].price = req.body.price;
    }

    res.locals.successmsg = 'Product updated successfully';
    res.render('edit_product', { product: products[id] });
});

app.get('/report', (req, res) => {
    res.render('report', { products: products });
});

app.post('/report', (req, res) => {
    const id = parseInt(req.body.id);
        if (isNaN(id) || id < 0 || id >= products.length) {
        res.locals.errormsg = 'Invalid product ID';
        res.render('report', { products: products });
        return;
    }

    fetch(`http://${HEADLESS_HOST}/`, { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json', 'X-Auth': HEADLESS_AUTH },
        body: JSON.stringify({ 
            actions: [
                {
                    type: 'request',
                    url: `http://${WEB_DOM}/`,
                },
                {
                    type: 'set-cookie',
                    name: 'flag',
                    value: FLAG
                },
                {
                    type: 'request',
                    url: `http://${WEB_DOM}/product/${req.body.id}`
                },
                {
                    "type": "sleep",
                    "time": 1
                }
            ]
         })
    }).then((r) => {
        if (r.status !== 200) {
            console.error('Report submission failed', r.status)
            res.locals.errormsg = 'Report submission failed, contact an admin if the problem persists';
        } else {
            res.locals.successmsg = 'Report submitted successfully';
        }
        res.render('report', { products: products });
    }).catch((err) => {
        console.error('Report submission failed', err)
        res.locals.errormsg = 'Report submission failed, contact an admin if the problem persists';
        res.render('report', { products: products });
    });
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});