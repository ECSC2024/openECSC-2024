from flask import Flask, render_template, session, request, redirect
from secret import get_flag

app = Flask(__name__)

app.secret_key = '97239eab12e26920780c7fb577070207cac676d508b6c388'


def fetch_products():
    # this will eventually be replaced by an api or a database
    return [
        {'id': '2ca3d864-920d-4380-9f67-8378718fd473', 'name': 'Film camera',
            'price': 70.00, 'image': '/static/f523abdc-aae2-4e09-94b5-5d08d8033740.jpg', 'description': 'Used film camera, still works, some scratches on the body, otherwise in good condition. Film not included.'},
        {'id': 'dab6997a-2610-4bb3-bff2-ae16137f8a38', 'name': 'Raspberry Pi 0',
            'price': 10.00, 'image': '/static/88f16051-729d-457b-858b-a09a5e0ad57d.jpg', 'description': 'Raspberry Pi 0, original packaging. Power supply not included.'},
        {'id': '8d6388ff-c581-4cac-916b-ec26a4406b2b', 'name': 'Set of 6 guitar picks',
            'price': 2.00, 'image': '/static/7b459338-f78e-4171-a744-f84d23f9e901.jpg', 'description': 'Set of 6 guitar picks, various thicknesses and materials.'},
        {'id': 'd79a654a-4f8c-4e0f-a7e0-313142e32c57', 'name': 'Solder spool',
            'price': 20.00, 'image': '/static/d142b139-775d-448d-b62f-a5497b82c35e.jpg', 'description': 'Lead-free solder spool, 1.4mm diameter, 100g.'},
        {'id': '7a0b9a83-93c2-4621-aa1c-5f91bed1b995', 'name': 'Metronome',
            'price': 50.00, 'image': '/static/a0289628-0152-4f3c-aa92-ef32add8dae0.jpg', 'description': 'Just so you can say you have one. We all know you\'ll never use it.'},
        {'id': '43d27d66-150b-4b41-a1ee-6c3e02c0a67c', 'name': 'Flag',
            'price': 999.97, 'image': '/static/7189201c-69da-4bc3-ade9-bf10b8f54dcf.jpg', 'description': get_flag()},
    ]


@app.add_template_filter
def formatCurrency(value):
    return "${:,.2f}".format(value)


@app.route('/')
def home():
    if not 'credit' in session:
        session['credit'] = 100

    return render_template('index.html', credit=session['credit'], products=fetch_products())


@app.route('/buy', methods=['POST', 'GET'])
def buy():
    if request.method == 'GET':
        return redirect('/')

    product_id = request.form.get('product_id')
    product = next((p for p in fetch_products() if p['id'] == product_id), None)

    if product is None:
        return 'Product not found', 404

    if not 'credit' in session:
        print('credit not in session?')
        return redirect('/')

    session['credit'] -= product['price']

    return render_template('product.html', credit=session['credit'], product=product)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
