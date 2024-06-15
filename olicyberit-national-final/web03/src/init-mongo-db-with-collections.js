db.getSiblingDB('admin').createUser({
	user: 'user',
	pwd: 'c3b658be14c71747e26d96a2811ab772',
	roles: [
		{
			role: 'readWrite',
			db: 'shop'
		}
	]
});

db.createCollection('users');
db.createCollection('products');
db.createCollection('orders');

db.products.insertMany([
	{
		name: 'Film camera',
		image: '/static/f523abdc-aae2-4e09-94b5-5d08d8033740.jpg',
		description:
			'Used film camera, still works, some scratches on the body, otherwise in good condition. Film not included.'
	},
	{
		name: 'Raspberry Pi 0',
		image: '/static/88f16051-729d-457b-858b-a09a5e0ad57d.jpg',
		description: 'Raspberry Pi 0, original packaging. Power supply not included.'
	},
	{
		name: 'Set of 6 guitar picks',
		image: '/static/7b459338-f78e-4171-a744-f84d23f9e901.jpg',
		description: 'Set of 6 guitar picks, various thicknesses and materials.'
	},
	{
		name: 'Solder spool',
		image: '/static/d142b139-775d-448d-b62f-a5497b82c35e.jpg',
		description: 'Lead-free solder spool, 1.4mm diameter, 100g.'
	},
	{
		name: 'Metronome',
		image: '/static/a0289628-0152-4f3c-aa92-ef32add8dae0.jpg',
		description: "Just so you can say you have one. We all know you'll never use it."
	}
]);
