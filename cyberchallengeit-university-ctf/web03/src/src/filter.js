function filter(data) {
	if (!data) return data;

	let newData = data;
	if (typeof data !== 'string') {
		newData = JSON.stringify(data);
	}
	// During development of the challenges the "u" key on my keyboard broke.
	// So enjoy solving this without the letter "u" :)
	// P.S.: yes, the flag contains many "u"s ;)
	newData = newData.replace(/u/gi, '');

	// Also let's filter out some bad words, that would be too easy otherwise, right?
	while (newData.match(/(hex|ascii|mid|sleep|where|when|select)/gi)) {
		newData = newData.replace(/hex/gi, '');
		newData = newData.replace(/ascii/gi, '');
		newData = newData.replace(/mid/gi, '');
		newData = newData.replace(/sleep/gi, '');
		newData = newData.replace(/where/gi, '');
		newData = newData.replace(/when/gi, '');
		newData = newData.replace(/select/gi, '');
	}

	if (typeof data !== 'string') {
		return JSON.parse(newData);
	}
	return newData;
}

// Middleware to filter requests and responses
export default function (req, res, next) {
	if (req.body) {
		req.body = JSON.parse(filter(JSON.stringify(req.body)));
	}
	if (req.query) {
		req.query = JSON.parse(filter(JSON.stringify(req.query)));
	}
	if (req.params) {
		req.params = JSON.parse(filter(JSON.stringify(req.params)));
	}

	const send = res.send;
	res.send = function (string) {
		const body = string instanceof Buffer ? string.toString() : string;
		send.call(this, filter(body));
	};

	next();
}
